"""SPECTER // passive recon console."""

from __future__ import annotations

import asyncio
import random
import time
from datetime import datetime, timezone

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Center, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Input,
    Label,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
)

from . import recon, report, signals

try:
    from textual.theme import Theme
except ImportError:  # textual < 0.86
    Theme = None

GREEN = "#00ff41"
MID = "#00a82d"
DIM = "#00561a"
RED = "#ff0033"
AMBER = "#ffb000"

BANNER = "\n".join(
    [
        "███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗ ",
        "██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗",
        "███████╗██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝",
        "╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══╝  ██╔══██╗",
        "███████║██║     ███████╗╚██████╗   ██║   ███████╗██║  ██║",
        "╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝",
    ]
)
GLITCH_CHARS = "▓▒░#@$%&*/\\|<>01"

TAGLINES = [
    "hello, friend.",
    "control is an illusion. recon is not.",
    "passive eyes. zero footprint.",
    "every system leaks. we just listen.",
    "know the target before the target knows you.",
    "the internet remembers everything. ask it.",
]

BOOT_LINES = [
    ("[*] booting SPECTER v0.1 ... made by CyberRaavan", DIM),
    ("[*] modules: dns rdap tls http ct-logs well-known api", DIM),
    ("[*] mode PASSIVE // no exploitation, no brute force, no port scans", DIM),
    ("[!] every target must be inside an authorized scope", AMBER),
    ("[+] hello, friend.", RED),
    ("[>] enter a target domain and hit EXECUTE", GREEN),
]

MODULES = ("dns", "rdap", "tls", "http", "ct", "wellknown", "api")
MODULE_LABELS = {
    "dns": "DNS",
    "rdap": "RDAP",
    "tls": "TLS",
    "http": "HTTP",
    "ct": "CT-LOGS",
    "wellknown": "WELL-KNOWN",
    "api": "API",
}
TABLE_COLUMNS = {
    "signals": ("SEV", "SIGNAL", "DETAIL"),
    "dns": ("TYPE", "VALUE"),
    "rdap": ("FIELD", "VALUE"),
    "tls": ("FIELD", "VALUE"),
    "http": ("FIELD", "VALUE"),
    "ct": ("#", "HOSTNAME", "CERTS"),
    "api": ("SOURCE", "ITEM", "DETAIL"),
}
API_ROW_LIMIT = 300
SEVERITY_STYLE = {"high": f"bold {RED}", "medium": f"bold {AMBER}", "low": "#d7ff00", "info": MID}
SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def describe(exc: BaseException) -> str:
    return str(exc) or exc.__class__.__name__


def summarize(name: str, data) -> str:
    if name == "dns":
        count = sum(len(v) for v in data["records"].values())
        return f"{count} records, DMARC {'present' if data['dmarc'] else 'absent'}"
    if name == "rdap":
        return f"registrar {data['registrar'] or 'unknown'}"
    if name == "tls":
        return f"{data['protocol']} cert from {data['issuer_org'] or data['issuer_cn']}, {data['days_left']}d left"
    if name == "http":
        return f"{data['status']} at {data['final_url']}"
    if name == "ct":
        return f"{len(data)} unique hostnames"
    if name == "api":
        specs = data.get("specs") or []
        parts = [
            f"{len(specs)} specs ({sum(len(s['endpoints']) for s in specs)} endpoints)",
            f"{len(data.get('docs_ui') or [])} docs UIs",
            f"{len(data.get('graphql') or [])} GraphQL",
            f"OIDC {'yes' if data.get('oidc') else 'no'}",
            f"{len((data.get('javascript') or {}).get('paths', []))} JS paths",
            f"{len(data.get('wayback') or [])} archived",
        ]
        if data.get("errors"):
            parts.append("partial: " + ", ".join(data["errors"]))
        return ", ".join(parts)
    found =[path for path, entry in data.items() if entry.get("body")]
    return "found " + ", ".join(found) if found else "nothing published"


class Banner(Static):
    """ASCII logo that glitches every few seconds."""

    def on_mount(self) -> None:
        self._restore()

    def _restore(self) -> None:
        self.update(Text(BANNER, style=f"bold {GREEN}"))
        self.set_timer(random.uniform(2.5, 6.0), self._glitch)

    def _glitch(self) -> None:
        text = Text()
        for ch in BANNER:
            if ch not in " \n" and random.random() < 0.06:
                text.append(random.choice(GLITCH_CHARS), style=f"bold {RED}")
            else:
                text.append(ch, style=f"bold {GREEN}")
        self.update(text)
        self.set_timer(0.12, self._restore)


class Tagline(Static):
    """Typewriter that cycles through taglines."""

    def on_mount(self) -> None:
        self._lines = random.sample(TAGLINES, len(TAGLINES))
        self._index = 0
        self._pos = 0
        self.set_interval(0.06, self._tick)

    def _tick(self) -> None:
        line = self._lines[self._index]
        self._pos += 1
        if self._pos <= len(line):
            self.update(Text(f"> {line[: self._pos]}█", style=RED))
        elif self._pos > len(line) + 60:
            self._index = (self._index + 1) % len(self._lines)
            self._pos = 0
        else:
            cursor = "█" if (self._pos // 8) % 2 == 0 else " "
            self.update(Text(f"> {line}{cursor}", style=RED))


class AuthGate(ModalScreen[bool]):
    """Scope confirmation before any target is touched."""

    BINDINGS = [Binding("escape", "deny", "Abort")]

    def __init__(self, target: str) -> None:
        super().__init__()
        self.target_domain = target

    def compose(self) -> ComposeResult:
        with Vertical(id="gate"):
            yield Label("[ RULES OF ENGAGEMENT ]", id="gate-title")
            yield Static(
                Text.assemble(
                    ("target  ", DIM),
                    (self.target_domain, f"bold {RED}"),
                    "\n\n",
                    (
                        "SPECTER queries public sources (DNS, RDAP, certificate transparency) "
                        "and makes one TLS handshake plus about 25 ordinary GET requests to the target "
                        "(homepage, well-known files, common API doc paths, a few same-site scripts).\n\n",
                        GREEN,
                    ),
                    ("Confirm this domain is inside an authorized engagement scope.", f"bold {AMBER}"),
                ),
                id="gate-body",
            )
            with Horizontal(id="gate-buttons"):
                yield Button("AUTHORIZED", id="gate-yes")
                yield Button("ABORT", id="gate-no")

    @on(Button.Pressed, "#gate-yes")
    def confirm(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#gate-no")
    def action_deny(self) -> None:
        self.dismiss(False)


class Specter(App):
    TITLE = "SPECTER"
    CSS_PATH = "specter.tcss"
    BINDINGS = [
        Binding("ctrl+s", "save_report", "Save report", priority=True),
        Binding("ctrl+l", "clear_log", "Clear log", priority=True),
        Binding("ctrl+q", "quit", "Quit", priority=True),
    ]

    def __init__(self, target: str | None = None) -> None:
        super().__init__()
        self.initial_target = target
        self.current_target: str | None = None
        self.authorized: set[str] = set()
        self.intel: dict = {}
        self.failures: dict = {}
        self.module_state: dict = {}
        self.scan_meta: dict = {}
        self._spin = 0

    def compose(self) -> ComposeResult:
        with Center():
            yield Banner(id="banner")
        yield Static(Text.assemble(("made by ", DIM), ("CyberRaavan", f"bold {RED}")), id="credit")
        yield Tagline(id="tagline")
        with Horizontal(id="command"):
            yield Static("root@specter:~#", id="prompt")
            yield Input(placeholder="target domain  (e.g. example.com)", id="target")
            yield Button("EXECUTE", id="execute")
        yield Static(id="status")
        with Horizontal(id="main"):
            with TabbedContent(id="results"):
                with TabPane("SIGNALS", id="tab-signals"):
                    yield DataTable(id="signals", cursor_type="row")
                with TabPane("DNS", id="tab-dns"):
                    yield DataTable(id="dns", cursor_type="row")
                with TabPane("RDAP", id="tab-rdap"):
                    yield DataTable(id="rdap", cursor_type="row")
                with TabPane("TLS", id="tab-tls"):
                    yield DataTable(id="tls", cursor_type="row")
                with TabPane("HTTP", id="tab-http"):
                    yield DataTable(id="http", cursor_type="row")
                with TabPane("CT-LOGS", id="tab-ct"):
                    yield DataTable(id="ct", cursor_type="row")
                with TabPane("WELL-KNOWN", id="tab-wellknown"):
                    yield RichLog(id="wellknown", wrap=True)
                with TabPane("API", id="tab-api"):
                    yield DataTable(id="api", cursor_type="row")
            yield RichLog(id="opslog", wrap=True)
        yield Footer()

    def on_mount(self) -> None:
        if Theme is not None:
            self.register_theme(
                Theme(
                    name="fsociety",
                    primary=GREEN,
                    secondary=RED,
                    accent=RED,
                    warning=AMBER,
                    error=RED,
                    success=GREEN,
                    foreground=GREEN,
                    background="#000000",
                    surface="#030a03",
                    panel="#001a00",
                    dark=True,
                )
            )
            self.theme = "fsociety"
        for table_id, columns in TABLE_COLUMNS.items():
            self.query_one(f"#{table_id}", DataTable).add_columns(*columns)
        self.query_one("#results").border_title = "INTEL"
        self.query_one("#opslog").border_title = "OPS LOG"
        target_input = self.query_one("#target", Input)
        if self.initial_target:
            target_input.value = self.initial_target
        target_input.focus()
        self.set_interval(0.1, self.render_status)
        self.boot()

    # ------------------------------------------------------------ helpers

    @work(group="boot")
    async def boot(self) -> None:
        for message, style in BOOT_LINES:
            self.log_line(message, style)
            await asyncio.sleep(0.25)

    def log_line(self, message: str, style: str = GREEN) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        self.query_one("#opslog", RichLog).write(Text.assemble((f"[{stamp}] ", DIM), (message, style)))

    def _fill(self, table_id: str, rows) -> None:
        table = self.query_one(f"#{table_id}", DataTable)
        table.clear()
        for row in rows:
            table.add_row(*("-" if cell is None else cell for cell in row))

    def render_status(self) -> None:
        self._spin = (self._spin + 1) % len(SPINNER)
        line = Text()
        line.append(" TARGET ", style=f"bold #000000 on {RED}")
        line.append(f" {self.current_target or '--'} ", style=f"bold {GREEN}")
        line.append("│ MODE ", style=DIM)
        line.append("PASSIVE ", style=f"bold {GREEN}")
        line.append("│ ", style=DIM)
        symbols = {
            "idle": ("·", DIM),
            "running": (SPINNER[self._spin], f"bold {AMBER}"),
            "done": ("✔", f"bold {GREEN}"),
            "failed": ("✘", f"bold {RED}"),
        }
        for module in MODULES:
            symbol, style = symbols[self.module_state.get(module, "idle")]
            line.append(f"{MODULE_LABELS[module]} {symbol}  ", style=style)
        self.query_one("#status", Static).update(line)

    # --------------------------------------------------------------- scan

    @on(Input.Submitted, "#target")
    @on(Button.Pressed, "#execute")
    def request_scan(self, event) -> None:
        raw = self.query_one("#target", Input).value
        try:
            domain = recon.normalize_target(raw)
        except ValueError as exc:
            self.log_line(f"[!] {exc}", f"bold {RED}")
            return
        if domain in self.authorized:
            self.start_scan(domain)
            return

        def on_gate(confirmed: bool | None) -> None:
            if confirmed:
                self.authorized.add(domain)
                self.log_line(f"[+] scope confirmed for {domain}", GREEN)
                self.start_scan(domain)
            else:
                self.log_line("[-] aborted: target not confirmed in scope", AMBER)

        self.push_screen(AuthGate(domain), on_gate)

    def start_scan(self, domain: str) -> None:
        self.current_target = domain
        self.intel = {}
        self.failures = {}
        self.module_state = {module: "running" for module in MODULES}
        for table_id in TABLE_COLUMNS:
            self.query_one(f"#{table_id}", DataTable).clear()
        self.query_one("#wellknown", RichLog).clear()
        self.run_scan(domain)

    @work(exclusive=True, group="scan")
    async def run_scan(self, domain: str) -> None:
        self.log_line(f"[*] target acquired: {domain}", f"bold {RED}")
        started = time.monotonic()
        self.scan_meta = {"target": domain, "started": datetime.now(timezone.utc).isoformat()}

        async def guarded(name, coro):
            try:
                return name, await coro, None
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                return name, None, exc

        async with recon.make_client() as client:
            jobs = {
                "dns": recon.dns_records(domain),
                "rdap": recon.rdap_lookup(client, domain),
                "tls": recon.tls_certificate(domain),
                "http": recon.http_probe(client, domain),
                "ct": recon.ct_subdomains(client, domain),
                "wellknown": recon.well_known(client, domain),
                "api": recon.api_recon(client, domain),
            }
            tasks = [asyncio.create_task(guarded(n, c)) for n, c in jobs.items()]
            try:
                for next_done in asyncio.as_completed(tasks):
                    name, data, exc = await next_done
                    label = MODULE_LABELS[name]
                    if exc is None:
                        self.intel[name] = data
                        self.module_state[name] = "done"
                        getattr(self, f"_render_{name}")(data)
                        self.log_line(f"[+] {label} :: {summarize(name, data)}", GREEN)
                    else:
                        self.failures[name] = describe(exc)
                        self.module_state[name] = "failed"
                        self.log_line(f"[x] {label} :: {describe(exc)}", RED)
                    self.render_signals()
            finally:
                for task in tasks:
                    task.cancel()

        self.scan_meta["finished"] = datetime.now(timezone.utc).isoformat()
        count = len(signals.derive(self.intel, self.failures, domain))
        self.log_line(
            f"[*] sweep complete in {time.monotonic() - started:.1f}s, {count} signals. ctrl+s saves the report",
            f"bold {GREEN}",
        )

    # ---------------------------------------------------------- renderers

    def render_signals(self) -> None:
        rows = []
        for sig in signals.derive(self.intel, self.failures, self.current_target):
            style = SEVERITY_STYLE[sig["severity"]]
            rows.append((Text(sig["severity"].upper(), style=style), Text(sig["title"], style=style), sig["detail"]))
        self._fill("signals", rows)

    def _render_dns(self, data: dict) -> None:
        rows = [
            (Text(rtype, style=f"bold {RED}"), value)
            for rtype, values in data["records"].items()
            for value in values
        ]
        rows += [(Text("DMARC", style=f"bold {RED}"), value) for value in data["dmarc"]]
        self._fill("dns", rows or [("--", "no records returned")])

    def _render_rdap(self, data: dict) -> None:
        dnssec = {True: "signed", False: "unsigned"}.get(data["dnssec"], "unknown")
        rows = [
            ("Queried", data["queried"]),
            ("Registrar", data["registrar"]),
            ("Registered", data["registered"]),
            ("Expires", data["expires"]),
            ("Updated", data["updated"]),
            ("Status", ", ".join(data["status"]) or None),
            ("DNSSEC", dnssec),
        ]
        rows += [("Nameserver", ns) for ns in data["nameservers"]]
        self._fill("rdap", rows)

    def _render_tls(self, data: dict) -> None:
        days = data["days_left"]
        days_style = RED if days is not None and days < 30 else GREEN
        issuer = " / ".join(filter(None, (data["issuer_org"], data["issuer_cn"]))) or None
        rows = [
            ("Subject CN", data["subject_cn"]),
            ("Issuer", issuer),
            ("Valid from", data["not_before"]),
            ("Valid until", data["not_after"]),
            ("Days left", Text(str(days), style=f"bold {days_style}")),
            ("Protocol", data["protocol"]),
            ("Cipher", data["cipher"]),
            ("Serial", data["serial"]),
        ]
        sans = data["sans"]
        rows += [("SAN", san) for san in sans[:50]]
        if len(sans) > 50:
            rows.append(("SAN", f"... +{len(sans) - 50} more"))
        self._fill("tls", rows)

    def _render_http(self, data: dict) -> None:
        rows = []
        if data["https_error"]:
            rows.append(("HTTPS error", Text(data["https_error"], style=RED)))
        rows += [
            ("Requested", data["url"]),
            ("Final URL", data["final_url"]),
            ("Status", f"{data['status']} {data['reason']}"),
            ("Title", data["title"]),
            ("Server", data["server"]),
            ("X-Powered-By", data["powered_by"]),
        ]
        rows += [("Redirect", hop) for hop in data["redirects"]]
        for header, value in data["security_headers"].items():
            cell = Text(f"✔ {value[:90]}", style=GREEN) if value else Text("✘ missing", style=f"bold {RED}")
            rows.append((header, cell))
        rows += [("Tech", tech) for tech in data["tech"]]
        rows += [("Cookie", cookie) for cookie in data["cookies"]]
        self._fill("http", rows)

    def _render_ct(self, data: list) -> None:
        rows = []
        for index, entry in enumerate(data, 1):
            host = entry["hostname"]
            notable = signals.is_notable(host, self.current_target) or signals.is_api_host(host, self.current_target)
            style = f"bold {RED}" if notable else GREEN
            rows.append((str(index), Text(host, style=style), str(entry["certs"])))
        self._fill("ct", rows or [("--", "no certificates found", "")])

    def _render_wellknown(self, data: dict) -> None:
        log = self.query_one("#wellknown", RichLog)
        log.clear()
        for path, entry in data.items():
            log.write(Text(f"── {path}", style=f"bold {RED}"))
            if entry.get("body"):
                log.write(Text(entry["body"].rstrip(), style=GREEN))
            elif entry.get("error"):
                log.write(Text(f"   error: {entry['error']}", style=AMBER))
            else:
                log.write(Text(f"   not published (HTTP {entry['status']})", style=DIM))
            log.write("")

    def _render_api(self, data: dict) -> None:
        hot = f"bold {RED}"
        rows = []
        for spec in data.get("specs") or []:
            title = " ".join(filter(None, (spec["title"], spec["api_version"]))) or "untitled"
            detail = f"{title} / OpenAPI {spec['spec_version']}"
            rows.append((Text("SPEC", style=hot), Text(spec["path"], style=hot), detail))
            rows += [("SPEC", "server", url) for url in spec["servers"]]
            rows.append(("SPEC", "auth", ", ".join(spec["auth"]) or Text("no security schemes declared", style=AMBER)))
            rows += [("ENDPOINT", f"{e['method']} {e['path']}", e["summary"]) for e in spec["endpoints"]]
        for ui in data.get("docs_ui") or []:
            rows.append((Text("DOCS-UI", style=hot), Text(ui["path"], style=hot), f"{ui['kind']} at {ui['final_url']}"))
        for gql in data.get("graphql") or []:
            detail = f"{gql['kind']} (HTTP {gql['status']})"
            rows.append((Text("GRAPHQL", style=hot), Text(gql["path"], style=hot), detail))
        if oidc := data.get("oidc"):
            rows += [("OIDC", key, str(value)) for key, value in oidc.items() if key != "grant_types"]
            if oidc.get("grant_types"):
                rows.append(("OIDC", "grant_types", ", ".join(oidc["grant_types"])))
        js = data.get("javascript") or {}
        rows += [("JS", item["path"], item["source"]) for item in js.get("paths", [])]
        rows += [("ARCHIVE", url, "web.archive.org") for url in data.get("wayback") or []]
        for name, error in (data.get("errors") or {}).items():
            rows.append((Text("ERROR", style=AMBER), name, error))
        if len(rows) > API_ROW_LIMIT:
            extra = len(rows) - API_ROW_LIMIT
            rows = rows[:API_ROW_LIMIT] + [("--", f"... +{extra} more rows", "full list in the saved report")]
        self._fill("api", rows or [("--", "no API surface found", "")])

    # ------------------------------------------------------------ actions

    def action_save_report(self) -> None:
        if not self.current_target or not (self.intel or self.failures):
            self.log_line("[!] nothing to save yet, run a scan first", AMBER)
            return
        sigs = signals.derive(self.intel, self.failures, self.current_target)
        json_path, md_path = report.save(self.current_target, self.intel, self.failures, sigs, self.scan_meta)
        self.log_line(f"[+] report saved: {md_path}", f"bold {GREEN}")
        self.log_line(f"[+] raw intel:    {json_path}", GREEN)

    def action_clear_log(self) -> None:
        self.query_one("#opslog", RichLog).clear()
