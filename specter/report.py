"""Write scan results to JSON (machine) and Markdown (humans)."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


def save(
    target: str,
    intel: dict,
    failures: dict,
    signals: list[dict],
    meta: dict,
    directory: Path = Path("reports"),
) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    stem = f"{target}_{datetime.now():%Y%m%d-%H%M%S}"
    json_path = directory / f"{stem}.json"
    md_path = directory / f"{stem}.md"

    payload = {
        "tool": "SPECTER",
        "author": "CyberRaavan",
        "target": target,
        "meta": meta,
        "signals": signals,
        "intel": intel,
        "failures": failures,
    }
    json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    md_path.write_text(to_markdown(target, intel, failures, signals, meta), encoding="utf-8")
    return json_path, md_path


def _cell(value) -> str:
    return str(value if value is not None else "-").replace("|", "\\|").replace("\n", " ")


def to_markdown(target: str, intel: dict, failures: dict, signals: list[dict], meta: dict) -> str:
    out = [
        f"# SPECTER recon report: {target}",
        "",
        f"- Started: {meta.get('started', '-')}",
        f"- Finished: {meta.get('finished', '-')}",
        "- Mode: passive (public sources plus ordinary HTTP/TLS requests)",
        "- Tool: SPECTER, made by CyberRaavan",
        "",
        "## Signals",
        "",
        "| Severity | Signal | Detail |",
        "|---|---|---|",
    ]
    out += [f"| {s['severity'].upper()} | {_cell(s['title'])} | {_cell(s['detail'])} |" for s in signals]

    if dns := intel.get("dns"):
        out += ["", "## DNS", ""]
        for rtype, values in dns["records"].items():
            out += [f"- **{rtype}**: `{v}`" for v in values]
        dmarc_label = f"DMARC (source: {dns['dmarc_source']})" if dns.get("dmarc_source") else "DMARC"
        out += [f"- **{dmarc_label}**: `{v}`" for v in dns["dmarc"]]
        out += [f"- **MTA-STS**: `{v}`" for v in dns.get("mta_sts", [])]
        out += [f"- **TLS-RPT**: `{v}`" for v in dns.get("tls_rpt", [])]
        out += [f"- **BIMI**: `{v}`" for v in dns.get("bimi", [])]

    for key, title in (("rdap", "Registration (RDAP)"), ("tls", "TLS certificate")):
        if data := intel.get(key):
            out += ["", f"## {title}", ""]
            for field, value in data.items():
                if isinstance(value, list):
                    value = ", ".join(map(str, value)) or "-"
                out.append(f"- **{field}**: {_cell(value)}")

    if http := intel.get("http"):
        out += ["", "## HTTP", ""]
        for field in ("url", "final_url", "status", "title", "server", "powered_by"):
            out.append(f"- **{field}**: {_cell(http.get(field))}")
        out.append(f"- **tech**: {', '.join(http['tech']) or '-'}")
        out += ["", "| Security header | Value |", "|---|---|"]
        out += [f"| {h} | {_cell(v or 'MISSING')} |" for h, v in http["security_headers"].items()]
        if cookies := http.get("cookie_security"):
            out += ["", "| Cookie | Secure | HttpOnly | SameSite |", "|---|---|---|---|"]
            out += [
                f"| {_cell(cookie['name'])} | {cookie.get('secure', False)} | "
                f"{cookie.get('http_only', False)} | {_cell(cookie.get('same_site'))} |"
                for cookie in cookies
            ]

    if (ct := intel.get("ct")) is not None:
        out += ["", f"## Certificate transparency ({len(ct)} hostnames)", "", "```"]
        out += [e["hostname"] for e in ct]
        out.append("```")

    if wk := intel.get("wellknown"):
        out += ["", "## Well-known files"]
        for path, entry in wk.items():
            out += ["", f"### {path}", ""]
            if entry.get("body"):
                out += ["```", entry["body"].rstrip(), "```"]
            else:
                out.append(f"not available (HTTP {entry.get('status') or entry.get('error')})")

    if api := intel.get("api"):
        out += ["", "## API surface"]
        for spec in api.get("specs") or []:
            title = " ".join(filter(None, (spec["title"], spec["api_version"]))) or "untitled"
            out += ["", f"### Spec `{spec['path']}`: {_cell(title)} (OpenAPI {spec['spec_version']})", ""]
            out.append(f"- **servers**: {_cell(', '.join(spec['servers']) or '-')}")
            out.append(f"- **auth**: {_cell(', '.join(spec['auth']) or 'none declared')}")
            out += ["", "| Method | Path | Summary |", "|---|---|---|"]
            out += [f"| {e['method']} | `{_cell(e['path'])}` | {_cell(e['summary'])} |" for e in spec["endpoints"]]
        if docs := api.get("docs_ui"):
            out += ["", "### Docs UIs", ""]
            out += [f"- `{d['path']}`: {d['kind']} at {d['final_url']}" for d in docs]
        if gql := api.get("graphql"):
            out += ["", "### GraphQL", ""]
            out += [f"- `{g['path']}`: {g['kind']} (HTTP {g['status']})" for g in gql]
        if oidc := api.get("oidc"):
            out += ["", "### OpenID Connect", ""]
            for key, value in oidc.items():
                if isinstance(value, list):
                    value = ", ".join(value) or "-"
                out.append(f"- **{key}**: {_cell(value)}")
        if js := (api.get("javascript") or {}).get("paths"):
            out += ["", f"### Paths in page JavaScript ({len(js)})", "", "```"]
            out += [f"{p['path']}    <- {p['source']}" for p in js]
            out.append("```")
        if wayback := api.get("wayback"):
            out += ["", f"### Archived API URLs ({len(wayback)})", "", "```"]
            out += wayback
            out.append("```")
        if api.get("errors"):
            out += ["", "### Partial failures", ""]
            out += [f"- **{k}**: {_cell(v)}" for k, v in api["errors"].items()]

    if failures:
        out += ["", "## Module failures", ""]
        out += [f"- **{m}**: {_cell(e)}" for m, e in failures.items()]

    return "\n".join(out) + "\n"
