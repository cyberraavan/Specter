"""Turn raw recon output into prioritized observations."""

from __future__ import annotations

import re
from datetime import datetime, timezone

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# Hostname tokens that usually point at non-production or internal surface.
NOTABLE = {
    "admin", "dev", "develop", "staging", "stage", "stg", "test", "testing", "uat",
    "qa", "beta", "preprod", "sandbox", "internal", "intranet", "corp", "vpn",
    "remote", "citrix", "jenkins", "ci", "git", "gitlab", "jira", "confluence",
    "grafana", "kibana", "prometheus", "sso", "auth", "login", "portal", "old",
    "legacy", "backup", "bak", "db", "sql", "phpmyadmin", "webmail", "owa", "exchange",
}

# Hostname tokens that point at API surface specifically.
API_TOKENS = {"api", "apis", "graphql", "gateway", "gw", "rest", "swagger", "openapi", "developer", "developers"}


def is_api_host(host: str, target: str | None) -> bool:
    sub = host
    if target and host.endswith(target):
        sub = host[: -len(target)].rstrip(".")
    return any(token in API_TOKENS for token in re.split(r"[.\-_]", sub) if token)

SECURITY_HEADERS_LOW = (
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)


def is_notable(host: str, target: str | None) -> bool:
    sub = host
    if target and host.endswith(target):
        sub = host[: -len(target)].rstrip(".")
    return any(token in NOTABLE for token in re.split(r"[.\-_]", sub) if token)


def _preview(items: list[str], limit: int = 8) -> str:
    text = ", ".join(items[:limit])
    return text + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


def derive(intel: dict, failures: dict, target: str | None = None) -> list[dict]:
    found: list[dict] = []

    def add(severity: str, title: str, detail: str = "") -> None:
        found.append({"severity": severity, "title": title, "detail": detail})

    _dns(intel.get("dns"), add)
    _rdap(intel.get("rdap"), add)
    _tls(intel.get("tls"), failures.get("tls", ""), add)
    _http(intel.get("http"), add)
    _ct(intel.get("ct"), target, add)
    _wellknown(intel.get("wellknown"), add)
    _api(intel.get("api"), intel.get("ct"), target, add)

    for module, error in failures.items():
        if module == "tls" and "CERTIFICATE_VERIFY_FAILED" in error:
            continue
        add("info", f"Module {module} failed", error)

    found.sort(key=lambda s: SEVERITY_ORDER[s["severity"]])
    return found


def _dns(dns: dict | None, add) -> None:
    if not dns:
        return
    records = dns["records"]
    spf = [t for t in records.get("TXT", []) if t.lower().startswith("v=spf1")]
    if not spf:
        add("medium", "No SPF record", "mail claiming to be from this domain cannot be validated")
    else:
        rule = spf[0].lower()
        if "+all" in rule:
            add("high", "SPF permits any sender (+all)", spf[0])
        elif "?all" in rule:
            add("medium", "SPF is neutral (?all)", spf[0])
        elif "~all" in rule:
            add("low", "SPF soft-fails (~all)", "spoofed mail is marked, not rejected")
        if len(spf) > 1:
            add("medium", "Multiple SPF records", "invalid per RFC 7208; receivers may ignore SPF")

    dmarc = [d for d in dns.get("dmarc", []) if d.lower().startswith("v=dmarc1")]
    if not dmarc:
        add("medium", "No DMARC policy", "domain is a candidate for email-spoofing scenarios")
    else:
        match = re.search(r"\bp=(\w+)", dmarc[0].lower())
        policy = match.group(1) if match else "?"
        if policy == "none":
            add("low", "DMARC is monitor-only (p=none)", dmarc[0])
        else:
            add("info", f"DMARC enforced (p={policy})", dmarc[0])

    if not records.get("CAA"):
        add("info", "No CAA record", "any public CA may issue certificates for this domain")
    if not records.get("MX"):
        add("info", "No MX records", "domain does not receive mail directly")


def _rdap(rdap: dict | None, add) -> None:
    if not rdap:
        return
    expires = rdap.get("expires")
    if expires:
        try:
            days = (datetime.fromisoformat(expires) - datetime.now(timezone.utc)).days
        except ValueError:
            days = None
        if days is not None and days < 60:
            add("medium", f"Domain registration expires in {days} days", expires)
    if rdap.get("dnssec") is False:
        add("info", "DNSSEC not enabled", "delegation is unsigned")


def _tls(tls: dict | None, error: str, add) -> None:
    if "CERTIFICATE_VERIFY_FAILED" in error:
        add("high", "TLS certificate failed verification", error)
    if not tls:
        return
    days = tls.get("days_left")
    if days is not None:
        if days < 0:
            add("high", "TLS certificate has expired", tls.get("not_after") or "")
        elif days < 30:
            add("medium", f"TLS certificate expires in {days} days", tls.get("not_after") or "")


def _http(http: dict | None, add) -> None:
    if not http:
        return
    if http.get("https_error"):
        add("medium", "HTTPS failed, fell back to HTTP", http["https_error"])
    final = http.get("final_url") or ""
    if final.startswith("http://"):
        add("medium", "Site served over plain HTTP", final)
    headers = http.get("security_headers", {})
    if final.startswith("https://") and not headers.get("strict-transport-security"):
        add("medium", "No HSTS header", "first visit can be downgraded to HTTP")
    missing = [h for h in SECURITY_HEADERS_LOW if not headers.get(h)]
    if missing:
        add("low", "Missing security headers", ", ".join(missing))
    server = http.get("server")
    if server and re.search(r"\d", server):
        add("low", "Server banner discloses version", server)
    if http.get("powered_by"):
        add("low", "X-Powered-By discloses stack", http["powered_by"])
    if http.get("tech"):
        add("info", "Technology fingerprint", ", ".join(http["tech"]))


def _ct(ct: list | None, target: str | None, add) -> None:
    if ct is None:
        return
    add("info", f"{len(ct)} hostnames in certificate transparency logs", "see CT-LOGS tab")
    notable = [e["hostname"] for e in ct if is_notable(e["hostname"], target)]
    if notable:
        add("low", f"{len(notable)} notable hostnames exposed via CT logs", _preview(notable))


def _wellknown(wk: dict | None, add) -> None:
    if not wk:
        return
    security = (wk.get("/.well-known/security.txt") or {}).get("body")
    if security:
        contacts = re.findall(r"(?im)^contact:\s*(\S+)", security)
        add("info", "security.txt published", ", ".join(contacts) or "no Contact field")
    else:
        add("info", "No security.txt", "no published vulnerability-disclosure contact")
    robots = (wk.get("/robots.txt") or {}).get("body")
    if robots:
        disallowed = re.findall(r"(?im)^\s*disallow:\s*(\S+)", robots)
        if disallowed:
            add("info", f"robots.txt lists {len(disallowed)} disallowed paths", _preview(disallowed))


def _api(api: dict | None, ct: list | None, target: str | None, add) -> None:
    if ct:
        hosts = [e["hostname"] for e in ct if is_api_host(e["hostname"], target)]
        if hosts:
            add("info", f"{len(hosts)} API hostnames in CT logs", _preview(hosts))
    if not api:
        return
    for spec in api.get("specs") or []:
        add(
            "medium",
            "Public API specification exposed",
            f"{spec['path']}: {len(spec['endpoints'])} endpoints documented",
        )
        if not spec["auth"]:
            add("low", "API spec declares no auth scheme", f"{spec['path']} has no securitySchemes")
    for ui in api.get("docs_ui") or []:
        add("medium", f"Interactive API docs exposed ({ui['kind']})", ui["final_url"])
    for gql in api.get("graphql") or []:
        severity = "medium" if gql["kind"] == "GraphQL IDE" else "low"
        add(severity, f"{gql['kind']} reachable", gql["path"])
    if oidc := api.get("oidc"):
        add("info", "OpenID Connect provider published", oidc.get("issuer", ""))
        if oidc.get("registration_endpoint"):
            add("low", "OIDC dynamic client registration advertised", oidc["registration_endpoint"])
    js_paths = [p["path"] for p in (api.get("javascript") or {}).get("paths", [])]
    if js_paths:
        add("info", f"{len(js_paths)} API paths referenced in page JavaScript", _preview(js_paths))
    archived = api.get("wayback") or []
    if archived:
        add("info", f"{len(archived)} archived API URLs on the Wayback Machine", _preview(archived))
