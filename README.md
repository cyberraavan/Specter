# SPECTER

```
███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗
██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
███████╗██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝
╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══╝  ██╔══██╗
███████║██║     ███████╗╚██████╗   ██║   ███████╗██║  ██║
╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

> hello, friend.

**Made by CyberRaavan**

SPECTER is a **low-touch recon console** for the first hours of an **authorized**
red team engagement or security assessment. You give it a domain. It runs seven
intel modules at the same time, shows the raw results in tabs, and turns them
into ranked **signals**: the findings worth looking at first.

It runs in your terminal as a full-screen app built with
[Textual](https://textual.textualize.io/).

---

## Table of contents

1. [Installation](#installation)
2. [Authorized use only](#authorized-use-only)
3. [What it does](#what-it-does)
4. [How it works](#how-it-works)
5. [Usage](#usage)
6. [The screen](#the-screen)
7. [Modules in detail](#modules-in-detail)
8. [Signals reference](#signals-reference)
9. [Reports](#reports)
10. [Troubleshooting](#troubleshooting)
11. [Project layout](#project-layout)
12. [Extending SPECTER](#extending-specter)
13. [License](#license)

---

## Installation

You need **Python 3.10 or newer**. The dependencies, `textual`, `httpx` and
`dnspython`, are installed automatically.

> **Private repository.** If this repository is private, `git clone` asks for
> a GitHub login and fails without one. Run `gh auth login` first, or ask the
> owner for access. Public repositories need no login.

### Linux (Kali, Ubuntu, Debian)

Kali and newer Debian-based systems block a global `pip install` with
`externally-managed-environment`. This script installs SPECTER inside its own
virtual environment, so your system Python is not touched.

**Script 1: install.** Copy the whole block, paste it in a terminal, and press
Enter. It is safe to run again: if `~/Specter` already exists, it updates it
instead of failing.

```bash
sudo apt update && sudo apt install -y git python3 python3-venv python3-pip && \
if [ -d ~/Specter/.git ]; then git -C ~/Specter pull; else git clone https://github.com/cyberraavan/Specter.git ~/Specter; fi && \
cd ~/Specter && \
python3 -m venv venv && \
./venv/bin/pip install --upgrade pip && \
./venv/bin/pip install -e . && \
sudo ln -sf ~/Specter/venv/bin/specter /usr/local/bin/specter && \
echo "SPECTER installed. Run it with: specter"
```

**Script 2: run.** After the install prints `SPECTER installed`, run:

```bash
specter
```

Or open it with a target already filled in:

```bash
specter example.com
```

You do not need to activate the virtual environment. The `specter` command
points straight into it.

**Update:** run Script 1 again.

**Uninstall:**

```bash
sudo rm -f /usr/local/bin/specter && rm -rf ~/Specter
```

### Windows (PowerShell)

You need Git and Python 3.10 or newer. If either is missing, install them
first, then open a new PowerShell window:

```powershell
winget install -e --id Git.Git
winget install -e --id Python.Python.3.12
```

**Script 1: install.** Copy the whole block, paste it in PowerShell, and
press Enter. It is safe to run again: an existing install is updated.

```powershell
$dir = "$HOME\Specter"
$env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
if (Test-Path "$dir\.git") { git -C $dir pull } else { git clone https://github.com/cyberraavan/Specter.git $dir }
if ($LASTEXITCODE) { throw "git step failed" }
python -m venv "$dir\venv"
if ($LASTEXITCODE) { throw "could not create the virtual environment" }
& "$dir\venv\Scripts\python.exe" -m pip install --upgrade pip
& "$dir\venv\Scripts\python.exe" -m pip install -e $dir
if ($LASTEXITCODE) { throw "pip install failed" }
New-Item -ItemType Directory -Force "$dir\bin" | Out-Null
Set-Content -Encoding ascii "$dir\bin\specter.cmd" "@`"$dir\venv\Scripts\specter.exe`" %*"
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ("$userPath" -notlike "*$dir\bin*") { [Environment]::SetEnvironmentVariable("Path", ("$userPath;$dir\bin").TrimStart(";"), "User") }
Write-Host "SPECTER installed. Open a new terminal and run: specter"
```

**Script 2: run.** Open a **new** PowerShell or Windows Terminal window, then run:

```powershell
specter
```

The script does not activate the virtual environment, so PowerShell's
script execution policy does not get in the way. It adds only the small
`Specter\bin` folder to your user PATH, not the virtual environment's Python.

**Uninstall:**

```powershell
$dir = "$HOME\Specter"
$p = ([Environment]::GetEnvironmentVariable("Path", "User") -split ";" | Where-Object { $_ -and $_ -ne "$dir\bin" }) -join ";"
[Environment]::SetEnvironmentVariable("Path", $p, "User")
Remove-Item -Recurse -Force $dir
```

### macOS and other Linux systems

```sh
git clone https://github.com/cyberraavan/Specter.git ~/Specter
cd ~/Specter
python3 -m venv venv
./venv/bin/pip install -e .
./venv/bin/specter
```

---

## Authorized use only

Only point SPECTER at domains that are inside a **written engagement scope**,
or at domains you own.

- Every new target goes through a **Rules of Engagement** prompt. Nothing is
  sent until you press **AUTHORIZED**.
- A confirmed domain is remembered only for the current session.
- Pressing **ABORT** or `Esc` cancels the scan, and nothing is sent.

SPECTER is low-touch by design. It does **no** port scanning, brute forcing,
fuzzing, directory busting, or exploitation. It does perform bounded HTTP
content discovery: up to about 28 ordinary GET requests to the explicitly
authorized target scope (the homepage, two well-known files, common API-documentation
paths, and up to 5 of its own script files). For an apex domain, its conventional
`www` host is also in scope; all other hosts, private/reserved IP destinations,
and chains longer than five hops are blocked.

---

## What it does

| Module     | Talks to                 | What it collects                                  |
|------------|--------------------------|---------------------------------------------------|
| DNS        | your system resolver     | DNS records, SPF/DMARC, MTA-STS, TLS-RPT, and BIMI |
| RDAP       | rdap.org (registries)    | registrar, dates, status, nameservers, DNSSEC     |
| CT-LOGS    | crt.sh                   | hostnames seen in certificate transparency logs   |
| TLS        | target, port 443         | issuer, expiry, SANs, protocol, cipher, and ALPN  |
| HTTP       | target                   | headers, title, tech fingerprint, cookie posture  |
| WELL-KNOWN | target                   | `/.well-known/security.txt` and `/robots.txt`     |
| API        | target, web.archive.org  | API specs, docs UIs, GraphQL, OIDC, JS API paths, archived API URLs |

Then the **signals engine** reads all of that and flags things like:

- weak email and SMTP-transport posture (SPF, DMARC, MTA-STS and TLS-RPT),
- expired or soon-expiring TLS certificates,
- missing or weak HSTS/CSP and insecure cookie attributes,
- version banners that leak the server stack,
- interesting subdomains such as `dev`, `staging`, `vpn`, `jenkins`, `admin`,
- exposed API documentation, Swagger or OpenAPI specs, and GraphQL IDEs.

---

## How it works

```
 you type a domain
        │
        ▼
 normalize_target()      "https://WWW.Example.com/x"  ->  "www.example.com"
        │                (rejects IPs, bad labels, empty input)
        ▼
 Rules of Engagement     confirm the domain is in scope
        │  AUTHORIZED
        ▼
 ┌─────────────── seven modules run in parallel (asyncio) ───────────────┐
 │  DNS    RDAP    TLS    HTTP    CT-LOGS    WELL-KNOWN    API           │
 └───────────────────────────────────┬───────────────────────────────────┘
                                 │ each result arrives as soon as it is ready
                                 ▼
        tab is filled  +  OPS LOG line  +  SIGNALS re-ranked live
                                 │
                                 ▼
               Ctrl+S  ->  reports/<domain>_<time>.md + .json
```

Step by step:

1. **Input cleanup.** Whatever you type, a URL, a hostname, or mixed case, is
   turned into a plain lowercase ASCII domain. International names are
   converted with IDNA. IP addresses and invalid names are rejected.
2. **Scope gate.** A modal asks you to confirm the domain is inside an
   authorized scope. Only after that does any network traffic start.
3. **Parallel sweep.** All seven modules start at once as async tasks. One
   shared HTTP client is used, with a 10 second timeout, a bounded connection
   pool, and the user agent `SPECTER-recon/0.1`. Target-bound redirects allow
   only the authorized hostname (or its apex/`www` pair for an apex target);
   non-public destinations and chains longer than five hops are blocked.
4. **Live results.** As each module finishes, its tab is filled, the status
   bar updates, and a line is written to the OPS LOG. If a module fails, the
   others keep running and the error is shown in red.
5. **Signals.** After every module result, the signal rules run again on
   everything collected so far, and the SIGNALS tab is re-sorted from HIGH to
   INFO.
6. **Export.** `Ctrl+S` writes a Markdown report for humans and a JSON file
   for tools.

---

## Usage

### Start it

```sh
specter                 # open the console with an empty target bar
specter example.com     # open with the target already filled in
python -m specter       # same thing, without the specter command
```

### Run a scan

1. Type the target domain in the bar at the top, for example `example.com`.
2. Press `Enter` or click **EXECUTE**.
3. Read the Rules of Engagement prompt. Press **AUTHORIZED** if the domain is
   in scope, or **ABORT** to cancel.
4. Watch the OPS LOG. Each module reports `[+]` on success or `[x]` on failure.
5. Open the **SIGNALS** tab first. It lists the most important findings at the top.
6. Use the other tabs for the raw data behind each signal.
7. Press `Ctrl+S` to save the report.

You can scan another domain right away. Type it and press `Enter` again.
A new scan clears the old results.

### Keyboard shortcuts

| Key      | Action                                          |
|----------|-------------------------------------------------|
| `Enter`  | run the sweep on the target in the input        |
| `Ctrl+S` | save the report to `reports/` (Markdown + JSON) |
| `Ctrl+L` | clear the ops log                               |
| `Ctrl+Q` | quit                                            |
| `Esc`    | abort on the Rules of Engagement prompt         |
| `Tab`    | move focus between input, button and tabs       |

For the best look, use a terminal with a dark background and a font that has
box-drawing characters, such as Windows Terminal with Cascadia Mono.

---

## The screen

```
┌──────────────────────────────────────────────────────────────┐
│  SPECTER banner                     > rotating tagline       │
├──────────────────────────────────────────────────────────────┤
│  [ target domain .............................. ] [EXECUTE]  │
├──────────────────────────────────────────────────────────────┤
│  status: DNS  RDAP  TLS  HTTP  CT-LOGS  WELL-KNOWN  API      │
├──────────────── INTEL ───────────────────────────────────────┤
│  SIGNALS | DNS | RDAP | TLS | HTTP | CT-LOGS | WELL-KNOWN |  │
│  API                                                         │
│                                                              │
│  SEV     SIGNAL                         DETAIL               │
│  HIGH    ...                                                 │
│  MEDIUM  ...                                                 │
├──────────────── OPS LOG ─────────────────────────────────────┤
│  [*] target acquired: example.com                            │
│  [+] DNS :: 14 records, DMARC present                        │
│  [x] CT-LOGS :: crt.sh timed out                             │
└──────────────────────────────────────────────────────────────┘
```

| Tab        | What you see                                                       |
|------------|--------------------------------------------------------------------|
| SIGNALS    | ranked findings with severity, title, and detail                   |
| DNS        | every record type, DMARC source, MTA-STS, TLS-RPT and BIMI         |
| RDAP       | registrar, created, expires, updated, status, nameservers, DNSSEC  |
| TLS        | subject, issuer, validity dates, protocol, cipher, ALPN and SANs   |
| HTTP       | status, redirects, headers, cookie attributes and tech fingerprint |
| CT-LOGS    | every hostname from crt.sh. Notable ones are shown in red          |
| WELL-KNOWN | the contents of `security.txt` and `robots.txt`, if published      |
| API        | specs and their endpoints, docs UIs, GraphQL, OIDC, JS and archived API paths |

Severity colours: **HIGH** red, **MEDIUM** amber, **LOW** yellow-green,
**INFO** green.

---

## Modules in detail

### DNS

- Uses your system resolver. If none is configured, it falls back to
  `1.1.1.1` and `8.8.8.8`.
- Queries A, AAAA, CNAME, MX, NS, TXT, SOA and CAA for the domain; and TXT
  for DMARC, MTA-STS, TLS-RPT and BIMI.
- DMARC organizational-domain fallback uses the Public Suffix List. When a
  parent record supplies policy for a subdomain, its source is shown explicitly
  and the `sp=` policy is honored.
- Split TXT strings are joined, so a long SPF record shows as one line.
- If the domain does not exist, the module fails with `NXDOMAIN`.

### RDAP

- RDAP is the modern replacement for WHOIS. Queries go through `rdap.org`,
  which forwards to the right registry.
- If you scan a subdomain such as `www.example.co.uk`, SPECTER walks up the
  name until a registry answers, so it finds `example.co.uk`.
- Some TLDs do not offer RDAP. In that case the module reports
  "no RDAP record found".

### TLS

- Opens one TLS connection to port 443 with normal certificate verification.
  If validation fails, it does not retry insecurely; the verification failure
  itself is retained as high-severity evidence.
- Reads the certificate subject, issuer, validity dates, serial number,
  Subject Alternative Names, protocol version, negotiated cipher and ALPN.
- If verification fails, that itself becomes a **HIGH** signal.

### HTTP

- Sends one `GET /` over HTTPS. If HTTPS fails, it tries plain HTTP and
  raises a signal about it.
- Follows only in-scope redirects and records the redirect chain. For an apex
  target, its conventional `www` host is included; redirects to any other
  host, non-public addresses, or more than five hops are blocked.
- Reads at most 512 KB of the page body.
- Collects the status, page title, `Server` and `X-Powered-By` headers, six
  security headers, cookie names, and cookie `Secure`/`HttpOnly`/`SameSite`
  attributes. Missing-header findings are suppressed on HTTP error responses.
- Evaluates HSTS duration and CSP directives such as `frame-ancestors`,
  `unsafe-inline`, `unsafe-eval`, and `object-src`; these are posture signals,
  not exploit claims.
- **Tech fingerprint** comes from three places:
  - headers such as `cf-ray` for Cloudflare or `x-vercel-id` for Vercel,
  - cookie names such as `PHPSESSID`, `JSESSIONID` or `laravel_session`,
  - page markers such as `/wp-content/`, `__NEXT_DATA__`, and the
    `<meta name="generator">` tag.

### CT-LOGS

- Every public TLS certificate is logged in certificate transparency logs.
  `crt.sh` lets you search them, which reveals hostnames the owner may not
  advertise.
- SPECTER queries `%.<domain>`, removes wildcards and duplicates, and counts
  how many certificates mention each hostname.
- Hostnames that contain words like `dev`, `staging`, `vpn`, `jenkins`,
  `admin`, `backup` or `phpmyadmin` are marked **notable** and shown in red.
- crt.sh is often slow. SPECTER waits up to 45 seconds and retries 3 times.

### WELL-KNOWN

- Fetches `/.well-known/security.txt` and `/robots.txt` over HTTPS.
- HTML responses are ignored, because many sites return their home page for
  missing files.
- Shows up to 6000 characters of each file.

### API

Maps the target's API surface. It runs six checks in parallel. If one check
fails, the others still report, and the failure shows as an ERROR row.

- **Published specs.** Sends one GET to each common OpenAPI or Swagger path,
  such as `/openapi.json`, `/swagger.json`, `/v2/api-docs`, `/v3/api-docs`,
  `/v2/swagger.json` and `/api/v3/openapi.json`. A response only counts if it
  is valid JSON with an `openapi` or `swagger` field and a `paths` object.
  SPECTER then lists every endpoint with its method and summary, the declared
  servers, and the auth schemes.
- **Docs UIs.** Checks `/`, `/swagger-ui.html`, `/swagger-ui/`, `/docs`,
  `/redoc` and `/api/docs` for Swagger UI, ReDoc, RapiDoc or Scalar. It looks
  for the library's own files or tags, not just the word, to avoid false hits.
- **GraphQL.** Sends a plain GET to `/graphql` and `/api/graphql`. It reports
  a GraphQL IDE such as GraphiQL, Playground or Apollo Sandbox, or a bare
  GraphQL endpoint. It does **not** send an introspection query.
- **OpenID Connect.** Reads `/.well-known/openid-configuration` and lists the
  issuer, auth, token, userinfo, JWKS and registration endpoints, plus the
  supported grant types.
- **JavaScript.** Reads the homepage and up to 5 same-site script files, and
  pulls out paths that start with `/api`, `/graphql`, `/rest` or `/v1` style
  version prefixes. Links to other domains are ignored.
- **Wayback Machine.** Asks `web.archive.org` for archived URLs of the domain
  and its subdomains whose path looks like an API. The target is not
  contacted for this check.

Hostnames such as `api.`, `graphql.`, `gateway.` and `developer.` in the
CT-LOGS results are counted as API surface. They are shown in red in the
CT-LOGS tab and reported once, as API hostnames, in SIGNALS.

The API tab shows at most 300 rows. The saved report has the full list.

---

## Signals reference

| Severity | Signal                                       | Why it matters                                      |
|----------|----------------------------------------------|-----------------------------------------------------|
| HIGH     | SPF permits any sender (`+all`)              | anyone can send mail as this domain                 |
| HIGH     | TLS certificate failed verification          | broken chain, wrong host, or self-signed            |
| HIGH     | TLS certificate has expired                  | users get warnings and learn to click past them     |
| MEDIUM   | No SPF record                                | sender cannot be validated                          |
| MEDIUM   | SPF is neutral (`?all`)                      | spoofed mail is not rejected                        |
| MEDIUM   | Multiple SPF records                         | invalid per RFC 7208, receivers may ignore SPF      |
| MEDIUM   | No DMARC policy                              | domain is a candidate for phishing scenarios        |
| MEDIUM   | Domain registration expires in under 60 days | risk of losing the domain if not renewed            |
| MEDIUM   | TLS certificate expires in under 30 days     | outage or browser warning soon                      |
| MEDIUM   | HTTPS failed, fell back to HTTP              | site may not support TLS properly                   |
| MEDIUM   | Site served over plain HTTP                  | traffic can be read or changed in transit           |
| MEDIUM   | No HSTS header                               | first visit can be downgraded to HTTP               |
| MEDIUM   | Cookies missing Secure                       | cookies can be sent over an HTTP downgrade          |
| MEDIUM   | GraphQL IDE reachable                        | GraphiQL or Playground is open to the internet      |
| LOW      | SPF soft-fails (`~all`)                      | spoofed mail is marked, not rejected                |
| LOW      | SPF has no terminal `all` mechanism          | unmatched senders can be evaluated inconsistently   |
| LOW      | DMARC is monitor-only (`p=none`)             | DMARC reports but does not block                    |
| LOW      | DMARC policy applies to less than 100%       | protection is only partially rolled out             |
| LOW      | Missing security headers                     | CSP, X-Frame-Options and similar are absent         |
| LOW      | HSTS is disabled or under 180 days           | downgrade protection is absent or short-lived       |
| LOW      | CSP permits unsafe script execution          | script policy has a risky directive                 |
| LOW      | Cookies missing HttpOnly                     | injected JavaScript may read the cookie             |
| LOW      | Server banner discloses version              | helps match the server to known CVEs                |
| LOW      | X-Powered-By discloses stack                 | reveals backend language or framework               |
| LOW      | Notable hostnames exposed via CT logs        | dev, staging or admin surface is public knowledge   |
| LOW      | GraphQL endpoint reachable                   | worth checking whether introspection is enabled     |
| LOW      | API spec declares no protected operations    | documentation indicates anonymous operations        |
| LOW      | OIDC dynamic client registration advertised  | anyone may be able to register an OAuth client      |
| INFO     | DMARC enforced                               | good posture, shown for context                     |
| INFO     | MTA-STS/TLS-RPT/BIMI advertised              | email and SMTP-transport posture context            |
| INFO     | No CAA record                                | any public CA may issue certificates                |
| INFO     | No MX records                                | domain does not receive mail directly               |
| INFO     | DNSSEC not enabled                           | delegation is unsigned                              |
| INFO     | Technology fingerprint                       | detected CDN, CMS and framework                     |
| INFO     | Public API specification or docs exposed     | inventory context; not a vulnerability by itself    |
| INFO     | Hostnames in CT logs                         | total count, see the CT-LOGS tab                    |
| INFO     | security.txt published or missing            | disclosure contact, or the lack of one              |
| INFO     | robots.txt disallowed paths                  | paths the owner does not want indexed               |
| INFO     | OpenID Connect provider published            | issuer and auth endpoints, shown for context        |
| INFO     | API hostnames in CT logs                     | `api.`, `gateway.` and similar subdomains           |
| INFO     | API paths referenced in page JavaScript      | endpoints the frontend calls                        |
| INFO     | Archived API URLs on the Wayback Machine     | old or forgotten endpoints that may still work      |
| INFO     | Module failed                                | a module errored, with the reason                   |

---

## Reports

Press `Ctrl+S` after a scan. Two files are written to a `reports/` folder in
the directory where you started SPECTER:

```
reports/
  example.com_20261018-171500.md     human-readable report
  example.com_20261018-171500.json   full data for scripts and other tools
```

The **Markdown** report contains scan times, the signals table, all DNS
records (including email-security TXT records), RDAP and TLS details, HTTP
headers with security-header and cookie-posture tables, the
CT hostname list, the well-known files, the full API surface with every
endpoint and archived URL, and any module failures.

The **JSON** file has this shape:

```json
{
  "tool": "SPECTER",
  "author": "CyberRaavan",
  "target": "example.com",
  "meta": { "target": "...", "started": "...", "finished": "..." },
  "signals": [ { "severity": "medium", "title": "...", "detail": "..." } ],
  "intel": { "dns": {}, "rdap": {}, "tls": {}, "http": {}, "ct": [], "wellknown": {}, "api": {} },
  "failures": { "ct": "crt.sh timed out ..." }
}
```

The `reports/` folder is in `.gitignore`, so client data is never committed
by accident.

---

## Troubleshooting

| Problem                                    | Fix                                                                 |
|--------------------------------------------|---------------------------------------------------------------------|
| `specter` is not recognized                | run Script 1 again, or use `~/Specter/venv/bin/specter`             |
| `error: externally-managed-environment`    | use the Linux install script, which uses a virtual environment      |
| `git clone` asks for a username            | the repo is private. Log in with `gh auth login` or ask for access  |
| `python3 -m venv` fails                    | install the venv package with `sudo apt install python3-venv`       |
| API shows `wayback: ReadTimeout`           | the Wayback Machine is slow. Run the sweep again later              |
| CT-LOGS fails or times out                 | crt.sh is overloaded. Run the sweep again in a few minutes          |
| RDAP says "no RDAP record found"           | the TLD does not offer RDAP. Use a normal WHOIS tool for it         |
| DNS says NXDOMAIN                          | check the spelling. The domain does not exist                       |
| TLS fails with `CERTIFICATE_VERIFY_FAILED` | that is a real finding, shown as a HIGH signal                      |
| Banner looks broken or shows `?`           | use Windows Terminal or another UTF-8 terminal with a modern font   |
| Colours look wrong                         | use a dark terminal theme with true colour support                  |
| "is not a valid domain name"               | SPECTER takes domains only, not IP addresses                        |

---

## Project layout

```
Specter/
  pyproject.toml     package metadata, dependencies, `specter` command, ruff settings
  README.md          this file
  LICENSE            proprietary license, all rights reserved
  .github/
    workflows/
      ci.yml         lint, compile and smoke test on every push
  specter/
    __init__.py      version and author
    __main__.py      command-line entry point (argparse)
    app.py           Textual UI, scope gate, scan orchestration, renderers
    recon.py         the seven recon modules and input normalization
    signals.py       rules that turn raw intel into ranked findings
    report.py        Markdown and JSON export
    specter.tcss     the green-on-black theme
```

---

## Extending SPECTER

**Add a signal rule.** Open `specter/signals.py`. Each module has a helper
such as `_dns` or `_http` that calls `add(severity, title, detail)`. Add your
check there. Severity must be `high`, `medium`, `low` or `info`.

**Flag more hostnames.** Add words to the `NOTABLE` set in
`specter/signals.py`.

**Detect more tech.** Add entries to `_HEADER_TECH`, `_COOKIE_TECH` or
`_BODY_TECH` in `specter/recon.py`.

**Add a module.** Write an async function in `recon.py`, add it to the `jobs`
dict in `run_scan` in `app.py`, add its name to `MODULES` and
`MODULE_LABELS`, add a tab, and write a `_render_<name>` method.

---

## License

Copyright (c) 2026 CyberRaavan. **All rights reserved.**

SPECTER is proprietary software. You may view the code, but you may not copy,
modify, redistribute, sell, or host it, or use it to train or build any AI or
machine learning model or dataset, without written permission from
CyberRaavan. See [LICENSE](LICENSE) for the full terms.

---

## Disclaimer

SPECTER is for authorized security testing and education. You are
responsible for having permission before scanning any domain. The author
accepts no liability for misuse.

**Made by CyberRaavan**
