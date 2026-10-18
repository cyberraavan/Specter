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


def _csp_directives(value: str) -> dict[str, list[str]]:
    """Return a conservative, lowercase representation of CSP directives."""
    directives: dict[str, list[str]] = {}
    for chunk in value.split(";"):
        parts = chunk.strip().lower().split()
        if parts:
            directives[parts[0]] = parts[1:]
    return directives


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
        terminal = re.search(r"(?:^|\s)([+?~-]?all)(?=\s|$)", rule)
        mechanism = terminal.group(1) if terminal else ""
        if mechanism == "+all":
            add("high", "SPF permits any sender (+all)", spf[0])
        elif mechanism == "?all":
            add("medium", "SPF is neutral (?all)", spf[0])
        elif mechanism == "~all":
            add("low", "SPF soft-fails (~all)", "spoofed mail is marked, not rejected")
        elif not mechanism:
            add("low", "SPF has no terminal all mechanism", "receivers may evaluate unmatched senders inconsistently")
        if len(spf) > 1:
            add("medium", "Multiple SPF records", "invalid per RFC 7208; receivers may ignore SPF")

    dmarc = [d for d in dns.get("dmarc", []) if d.lower().startswith("v=dmarc1")]
    if not dmarc:
        add("medium", "No DMARC policy", "domain is a candidate for email-spoofing scenarios")
    else:
        tags = {
            key.strip().lower(): value.strip().lower()
            for key, value in (part.split("=", 1) for part in dmarc[0].split(";") if "=" in part)
        }
        policy = tags.get("p", "?")
        if dns.get("dmarc_source") and dns.get("dmarc_source") != dns.get("dmarc_query"):
            policy = tags.get("sp", policy)
        if policy == "none":
            add("low", "DMARC is monitor-only (p=none)", dmarc[0])
        else:
            detail = dmarc[0]
            if dns.get("dmarc_source"):
                detail = f"source: {dns['dmarc_source']}; {detail}"
            add("info", f"DMARC enforced (p={policy})", detail)
        with_pct = tags.get("pct")
        if with_pct and with_pct.isdigit() and int(with_pct) < 100:
            add("low", f"DMARC policy applies to only {with_pct}% of mail", dmarc[0])

    if not records.get("CAA"):
        add("info", "No CAA record", "any public CA may issue certificates for this domain")
    if not records.get("MX"):
        add("info", "No MX records", "domain does not receive mail directly")
    else:
        mta_sts = [record for record in dns.get("mta_sts", []) if record.lower().startswith("v=stsv1")]
        tls_rpt = [record for record in dns.get("tls_rpt", []) if record.lower().startswith("v=tlsrptv1")]
        bimi = [record for record in dns.get("bimi", []) if record.lower().startswith("v=bimi1")]
        if mta_sts:
            add("info", "MTA-STS policy advertised", mta_sts[0])
        else:
            add("info", "MTA-STS not advertised", "inbound SMTP TLS policy is not discoverable via DNS")
        if tls_rpt:
            add("info", "TLS-RPT reporting advertised", tls_rpt[0])
        if bimi:
            add("info", "BIMI record published", bimi[0])


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
    if tls.get("verification_error"):
        add("high", "TLS certificate failed verification", tls["verification_error"])
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
    response_is_error = isinstance(http.get("status"), int) and http["status"] >= 400
    if response_is_error:
        add(
            "info",
            "HTTP posture observed on an error response",
            f"HTTP {http['status']}; missing-header signals suppressed",
        )
    hsts = headers.get("strict-transport-security", "")
    if final.startswith("https://") and not hsts and not response_is_error:
        add("medium", "No HSTS header", "first visit can be downgraded to HTTP")
    elif hsts:
        max_age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", hsts, re.I)
        if not max_age:
            add("low", "Malformed HSTS policy", hsts)
        elif int(max_age.group(1)) == 0:
            add("medium", "HSTS is disabled (max-age=0)", hsts)
        elif int(max_age.group(1)) < 15_552_000:
            add("low", "HSTS max-age is under 180 days", hsts)
    csp = headers.get("content-security-policy", "")
    missing = [h for h in SECURITY_HEADERS_LOW if not headers.get(h)]
    if "x-frame-options" in missing and re.search(r"(?:^|;)\s*frame-ancestors\s+", csp, re.I):
        missing.remove("x-frame-options")
    if missing and not response_is_error:
        add("low", "Missing security headers", ", ".join(missing))
    if csp:
        directives = _csp_directives(csp)
        script_sources = directives.get("script-src", directives.get("default-src", []))
        if "'unsafe-eval'" in script_sources:
            add("low", "CSP permits unsafe script evaluation", "script-src contains 'unsafe-eval'")
        has_nonce_or_hash = any(source.startswith("'nonce-") or source.startswith("'sha") for source in script_sources)
        if "'unsafe-inline'" in script_sources and not has_nonce_or_hash:
            add(
                "low",
                "CSP permits unrestricted inline scripts",
                "script-src contains 'unsafe-inline' without nonce/hash",
            )
        if "object-src" not in directives:
            add("info", "CSP does not restrict plugin content", "object-src is not set")
    if final.startswith("https://"):
        cookies = http.get("cookie_security") or []
        insecure = [cookie["name"] for cookie in cookies if not cookie.get("secure")]
        no_httponly = [cookie["name"] for cookie in cookies if not cookie.get("http_only")]
        same_site_none = [
            cookie["name"]
            for cookie in cookies
            if cookie.get("same_site") == "none" and not cookie.get("secure")
        ]
        if insecure:
            add("medium", "Cookies missing Secure attribute", _preview(insecure))
        if no_httponly:
            add("low", "Cookies missing HttpOnly attribute", _preview(no_httponly))
        if same_site_none:
            add("low", "SameSite=None cookies are not Secure", _preview(same_site_none))
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
            "info",
            "Public API specification exposed",
            f"{spec['path']}: {len(spec['endpoints'])} endpoints documented",
        )
        total = spec.get("operations_total", len(spec["endpoints"]))
        protected = spec.get("protected_operations", 0)
        if total and protected == 0:
            detail = f"{spec['path']}: {total} operations appear anonymous"
            add("low", "API spec declares no protected operations", detail)
        elif total and protected < total:
            detail = f"{spec['path']}: {total - protected}/{total} operations"
            add("info", "API spec includes anonymous operations", detail)
    for ui in api.get("docs_ui") or []:
        add("info", f"Interactive API docs exposed ({ui['kind']})", ui["final_url"])
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
