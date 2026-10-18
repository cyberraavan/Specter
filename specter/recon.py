"""Recon modules.

Everything here is low-touch: DNS goes through your normal resolver, RDAP and
crt.sh are third-party public services, and the target itself only sees one
TLS handshake and a few ordinary GET requests - the same as a browser visit.
"""

from __future__ import annotations

import asyncio
import contextlib
import html
import re
import ssl
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlsplit

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

USER_AGENT = "Mozilla/5.0 (compatible; SPECTER-recon/0.1; passive OSINT)"
RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")
SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)
WELL_KNOWN_PATHS = ("/.well-known/security.txt", "/robots.txt")
BODY_LIMIT = 512 * 1024

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def normalize_target(raw: str) -> str:
    """Turn user input (domain, URL, hostname) into a bare ASCII domain."""
    value = raw.strip().lower()
    if not value:
        raise ValueError("no target given")
    if "://" not in value:
        value = "//" + value
    host = (urlsplit(value).hostname or "").rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError(f"'{raw.strip()}' is not a valid domain name") from None
    labels = host.split(".")
    if (
        len(labels) < 2
        or len(host) > 253
        or labels[-1].isdigit()
        or not all(_LABEL.match(label) for label in labels)
    ):
        raise ValueError(f"'{raw.strip()}' is not a valid domain name")
    return host


def make_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        timeout=httpx.Timeout(10.0, connect=5.0),
        follow_redirects=True,
    )


# --------------------------------------------------------------------- DNS


def _resolver() -> dns.asyncresolver.Resolver:
    try:
        resolver = dns.asyncresolver.Resolver()
    except dns.resolver.NoResolverConfiguration:
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.lifetime = 6.0
    return resolver


def _join_txt(value: str) -> str:
    """'"v=spf1 include:a" " -all"' -> 'v=spf1 include:a -all'"""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', value)
    return "".join(parts) if parts else value


async def dns_records(domain: str) -> dict:
    resolver = _resolver()

    async def query(name: str, rtype: str) -> list[str]:
        try:
            answer = await resolver.resolve(name, rtype)
        except dns.resolver.NXDOMAIN:
            if name == domain:
                raise LookupError(f"{domain} does not exist (NXDOMAIN)") from None
            return []
        except dns.exception.DNSException:
            return []
        return sorted(record.to_text() for record in answer)

    values = await asyncio.gather(
        *(query(domain, rtype) for rtype in RECORD_TYPES),
        query(f"_dmarc.{domain}", "TXT"),
    )
    records = dict(zip(RECORD_TYPES, values[:-1]))
    records["TXT"] = [_join_txt(v) for v in records["TXT"]]
    return {"records": records, "dmarc": [_join_txt(v) for v in values[-1]]}


# -------------------------------------------------------------------- RDAP


def _vcard_name(entity: dict) -> str | None:
    vcard = entity.get("vcardArray")
    if not (isinstance(vcard, list) and len(vcard) == 2):
        return None
    for prop in vcard[1]:
        if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn":
            return str(prop[3])
    return None


async def rdap_lookup(client: httpx.AsyncClient, domain: str) -> dict:
    # Walk up from the given name until the registry knows it, so that
    # www.example.co.uk ends up at example.co.uk without a suffix list.
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        response = await client.get(
            f"https://rdap.org/domain/{candidate}",
            headers={"Accept": "application/rdap+json, application/json"},
        )
        if response.status_code == 404:
            continue
        response.raise_for_status()
        return _parse_rdap(response.json(), candidate)
    raise LookupError("no RDAP record found (the TLD may not offer RDAP)")


def _parse_rdap(data: dict, queried: str) -> dict:
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    registrar = None
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            registrar = _vcard_name(entity) or entity.get("handle")
    return {
        "queried": queried,
        "registrar": registrar,
        "registered": events.get("registration"),
        "expires": events.get("expiration"),
        "updated": events.get("last changed"),
        "status": data.get("status", []),
        "nameservers": sorted(
            ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])
        ),
        "dnssec": (data.get("secureDNS") or {}).get("delegationSigned"),
    }


# --------------------------------------------------------------------- TLS


def _rdn_dict(rdns) -> dict:
    out = {}
    for rdn in rdns:
        for key, value in rdn:
            out[key] = value
    return out


def _cert_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=timezone.utc)


async def tls_certificate(domain: str, port: int = 443) -> dict:
    context = ssl.create_default_context()
    _, writer = await asyncio.wait_for(
        asyncio.open_connection(domain, port, ssl=context, server_hostname=domain),
        timeout=8,
    )
    try:
        cert = writer.get_extra_info("peercert") or {}
        cipher = writer.get_extra_info("cipher")
        ssl_object = writer.get_extra_info("ssl_object")
        protocol = ssl_object.version() if ssl_object else None
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), 2)

    subject = _rdn_dict(cert.get("subject", ()))
    issuer = _rdn_dict(cert.get("issuer", ()))
    not_before = _cert_time(cert.get("notBefore"))
    not_after = _cert_time(cert.get("notAfter"))
    days_left = (not_after - datetime.now(timezone.utc)).days if not_after else None
    return {
        "subject_cn": subject.get("commonName"),
        "issuer_cn": issuer.get("commonName"),
        "issuer_org": issuer.get("organizationName"),
        "not_before": not_before.isoformat() if not_before else None,
        "not_after": not_after.isoformat() if not_after else None,
        "days_left": days_left,
        "protocol": protocol,
        "cipher": cipher[0] if cipher else None,
        "serial": cert.get("serialNumber"),
        "sans": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"],
    }


# -------------------------------------------------------------------- HTTP

_HEADER_TECH = (
    ("cf-ray", "Cloudflare"),
    ("x-amz-cf-id", "Amazon CloudFront"),
    ("x-fastly-request-id", "Fastly"),
    ("x-vercel-id", "Vercel"),
    ("x-nf-request-id", "Netlify"),
    ("x-github-request-id", "GitHub Pages"),
    ("x-azure-ref", "Azure Front Door"),
    ("x-akamai-transformed", "Akamai"),
    ("x-drupal-cache", "Drupal"),
    ("x-shopify-stage", "Shopify"),
)
_COOKIE_TECH = (
    ("phpsessid", "PHP"),
    ("jsessionid", "Java servlet"),
    ("asp.net_sessionid", "ASP.NET"),
    ("laravel_session", "Laravel"),
    ("ci_session", "CodeIgniter"),
    ("wordpress_", "WordPress"),
    ("wp-settings", "WordPress"),
    ("_shopify", "Shopify"),
    ("connect.sid", "Express (Node.js)"),
)
_BODY_TECH = (
    ("/wp-content/", "WordPress"),
    ("drupal-settings-json", "Drupal"),
    ('content="joomla', "Joomla"),
    ("__next_data__", "Next.js"),
    ("__nuxt", "Nuxt"),
    ("___gatsby", "Gatsby"),
    ("ng-version=", "Angular"),
    ("cdn.shopify.com", "Shopify"),
    ("static.wixstatic.com", "Wix"),
    ("squarespace.com", "Squarespace"),
    ("/_astro/", "Astro"),
)


def _fingerprint(headers: httpx.Headers, cookies: list[str], body: str) -> list[str]:
    found: list[str] = []

    def add(name: str) -> None:
        if name not in found:
            found.append(name)

    server = headers.get("server", "").lower()
    if server.startswith("cloudflare"):
        add("Cloudflare")
    if "akamai" in server:
        add("Akamai")
    for header, name in _HEADER_TECH:
        if header in headers:
            add(name)
    for cookie in cookies:
        for prefix, name in _COOKIE_TECH:
            if cookie.lower().startswith(prefix):
                add(name)
    lowered = body.lower()
    for marker, name in _BODY_TECH:
        if marker in lowered:
            add(name)
    generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if generator:
        add(f"generator: {html.unescape(generator.group(1))[:60]}")
    return found


async def _read_capped(response: httpx.Response, limit: int) -> str:
    chunks, size = [], 0
    async for chunk in response.aiter_bytes():
        chunks.append(chunk)
        size += len(chunk)
        if size >= limit:
            break
    raw = b"".join(chunks)[:limit]
    try:
        return raw.decode(response.charset_encoding or "utf-8", errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


async def http_probe(client: httpx.AsyncClient, domain: str) -> dict:
    https_error = None
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        try:
            async with client.stream("GET", url) as response:
                body = await _read_capped(response, BODY_LIMIT)
        except httpx.HTTPError as exc:
            if scheme == "https":
                https_error = str(exc) or exc.__class__.__name__
                continue
            raise
        headers = response.headers
        cookies = [c.split("=", 1)[0].strip() for c in headers.get_list("set-cookie")]
        title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        return {
            "url": url,
            "final_url": str(response.url),
            "status": response.status_code,
            "reason": response.reason_phrase,
            "redirects": [str(hop.url) for hop in response.history],
            "title": " ".join(html.unescape(title.group(1)).split())[:120] if title else None,
            "server": headers.get("server"),
            "powered_by": headers.get("x-powered-by"),
            "security_headers": {h: headers.get(h) for h in SECURITY_HEADERS},
            "cookies": cookies,
            "tech": _fingerprint(headers, cookies, body),
            "headers": {k.lower(): v for k, v in headers.items()},
            "https_error": https_error,
        }
    raise RuntimeError("unreachable")


# ----------------------------------------------- certificate transparency


async def ct_subdomains(client: httpx.AsyncClient, domain: str) -> list[dict]:
    params = {"q": f"%.{domain}", "output": "json"}
    timeout = httpx.Timeout(45.0, connect=10.0)
    for attempt in range(3):
        try:
            response = await client.get("https://crt.sh/", params=params, timeout=timeout)
        except httpx.TimeoutException:
            if attempt == 2:
                raise RuntimeError("crt.sh timed out (it is often overloaded; retry later)") from None
            continue
        if response.status_code >= 500 and attempt < 2:
            await asyncio.sleep(2 * (attempt + 1))
            continue
        if response.status_code >= 400:
            raise RuntimeError(
                f"crt.sh unavailable (HTTP {response.status_code}); it is often overloaded, retry later"
            )
        break
    try:
        rows = response.json()
    except ValueError:
        raise RuntimeError("crt.sh returned a non-JSON response (overloaded? retry later)") from None

    counts: Counter[str] = Counter()
    for row in rows:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.")
            if name == domain or name.endswith("." + domain):
                counts[name] += 1
    return [{"hostname": name, "certs": counts[name]} for name in sorted(counts)]


# -------------------------------------------------------------- well-known


async def well_known(client: httpx.AsyncClient, domain: str) -> dict:
    found = {}
    for path in WELL_KNOWN_PATHS:
        entry: dict = {"status": None, "body": None}
        try:
            response = await client.get(f"https://{domain}{path}")
            entry["status"] = response.status_code
            content_type = response.headers.get("content-type", "").lower()
            if response.status_code == 200 and "html" not in content_type:
                entry["body"] = response.text[:6000]
        except httpx.HTTPError as exc:
            entry["error"] = str(exc) or exc.__class__.__name__
        found[path] = entry
    return found
