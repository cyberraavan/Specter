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

SPECTER is a **passive recon console** for the first hours of an **authorized**
red team engagement or security assessment. You give it a domain. It runs six
intel modules at the same time, shows the raw results in tabs, and turns them
into ranked **signals**: the findings worth looking at first.

It runs in your terminal as a full-screen app built with
[Textual](https://textual.textualize.io/).

---

## Table of contents

1. [Authorized use only](#authorized-use-only)
2. [What it does](#what-it-does)
3. [How it works](#how-it-works)
4. [Installation](#installation)
5. [Usage](#usage)
6. [The screen](#the-screen)
7. [Modules in detail](#modules-in-detail)
8. [Signals reference](#signals-reference)
9. [Reports](#reports)
10. [Troubleshooting](#troubleshooting)
11. [Project layout](#project-layout)
12. [Extending SPECTER](#extending-specter)

---

## Authorized use only

Only point SPECTER at domains that are inside a **written engagement scope**,
or at domains you own.

- Every new target goes through a **Rules of Engagement** prompt. Nothing is
  sent until you press **AUTHORIZED**.
- A confirmed domain is remembered only for the current session.
- Pressing **ABORT** or `Esc` cancels the scan, and nothing is sent.

SPECTER is low-touch by design. It does **no** port scanning, brute forcing,
fuzzing, directory busting, or exploitation. The target sees roughly what it
would see from one browser visit.

---

## What it does

| Module     | Talks to                 | What it collects                                  |
|------------|--------------------------|---------------------------------------------------|
| DNS        | your system resolver     | A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, and DMARC  |
| RDAP       | rdap.org (registries)    | registrar, dates, status, nameservers, DNSSEC     |
| CT-LOGS    | crt.sh                   | hostnames seen in certificate transparency logs   |
| TLS        | target, port 443         | one handshake: issuer, expiry, SANs, protocol     |
| HTTP       | target                   | one GET of `/`: headers, title, tech fingerprint  |
| WELL-KNOWN | target                   | `/.well-known/security.txt` and `/robots.txt`     |

Then the **signals engine** reads all of that and flags things like:

- weak email spoofing protection (SPF and DMARC),
- expired or soon-expiring TLS certificates,
- missing HSTS and other security headers,
- version banners that leak the server stack,
- interesting subdomains such as `dev`, `staging`, `vpn`, `jenkins`, `admin`.

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
 ┌──────────── six modules run in parallel (asyncio) ────────────┐
 │  DNS     RDAP     TLS     HTTP     CT-LOGS     WELL-KNOWN      │
 └───────────────────────────────┬───────────────────────────────┘
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
3. **Parallel sweep.** All six modules start at once as async tasks. One
   shared HTTP client is used, with a 10 second timeout and the user agent
   `SPECTER-recon/0.1`.
4. **Live results.** As each module finishes, its tab is filled, the status
   bar updates, and a line is written to the OPS LOG. If a module fails, the
   others keep running and the error is shown in red.
5. **Signals.** After every module result, the signal rules run again on
   everything collected so far, and the SIGNALS tab is re-sorted from HIGH to
   INFO.
6. **Export.** `Ctrl+S` writes a Markdown report for humans and a JSON file
   for tools.

---

## Installation

You need **Python 3.10 or newer** and `pip`.

Dependencies, installed automatically:

- `textual` 0.86 or newer, for the terminal UI
- `httpx` 0.27 or newer, for HTTP requests
- `dnspython` 2.6 or newer, for DNS lookups

### Windows (PowerShell)

```powershell
git clone https://github.com/cyberraavan/Specter.git
cd Specter
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

If PowerShell blocks the activate script, run this once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### Linux and macOS

```sh
git clone https://github.com/cyberraavan/Specter.git
cd Specter
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Check the install

```sh
specter --help
```

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
│  module status: DNS  RDAP  TLS  HTTP  CT-LOGS  WELL-KNOWN    │
├──────────────── INTEL ───────────────────────────────────────┤
│  SIGNALS | DNS | RDAP | TLS | HTTP | CT-LOGS | WELL-KNOWN    │
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
| DNS        | every record type, plus the DMARC record                           |
| RDAP       | registrar, created, expires, updated, status, nameservers, DNSSEC  |
| TLS        | subject, issuer, validity dates, days left, protocol, cipher, SANs |
| HTTP       | status, redirects, title, server, security headers, cookies, tech  |
| CT-LOGS    | every hostname from crt.sh. Notable ones are shown in red          |
| WELL-KNOWN | the contents of `security.txt` and `robots.txt`, if published      |

Severity colours: **HIGH** red, **MEDIUM** amber, **LOW** yellow-green,
**INFO** green.

---

## Modules in detail

### DNS

- Uses your system resolver. If none is configured, it falls back to
  `1.1.1.1` and `8.8.8.8`.
- Queries A, AAAA, CNAME, MX, NS, TXT, SOA and CAA for the domain, and TXT for
  `_dmarc.<domain>`.
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
- Reads the certificate subject, issuer, validity dates, serial number,
  Subject Alternative Names, protocol version and cipher.
- If verification fails, that itself becomes a **HIGH** signal.

### HTTP

- Sends one `GET /` over HTTPS. If HTTPS fails, it tries plain HTTP and
  raises a signal about it.
- Follows redirects and records the redirect chain.
- Reads at most 512 KB of the page body.
- Collects the status, page title, `Server` and `X-Powered-By` headers, six
  security headers, and cookie names.
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
| LOW      | SPF soft-fails (`~all`)                      | spoofed mail is marked, not rejected                |
| LOW      | DMARC is monitor-only (`p=none`)             | DMARC reports but does not block                    |
| LOW      | Missing security headers                     | CSP, X-Frame-Options and similar are absent         |
| LOW      | Server banner discloses version              | helps match the server to known CVEs                |
| LOW      | X-Powered-By discloses stack                 | reveals backend language or framework               |
| LOW      | Notable hostnames exposed via CT logs        | dev, staging or admin surface is public knowledge   |
| INFO     | DMARC enforced                               | good posture, shown for context                     |
| INFO     | No CAA record                                | any public CA may issue certificates                |
| INFO     | No MX records                                | domain does not receive mail directly               |
| INFO     | DNSSEC not enabled                           | delegation is unsigned                              |
| INFO     | Technology fingerprint                       | detected CDN, CMS and framework                     |
| INFO     | Hostnames in CT logs                         | total count, see the CT-LOGS tab                    |
| INFO     | security.txt published or missing           | disclosure contact, or the lack of one              |
| INFO     | robots.txt disallowed paths                  | paths the owner does not want indexed               |
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
records, RDAP and TLS details, HTTP headers with a security-header table, the
CT hostname list, the well-known files, and any module failures.

The **JSON** file has this shape:

```json
{
  "tool": "SPECTER",
  "author": "CyberRaavan",
  "target": "example.com",
  "meta": { "target": "...", "started": "...", "finished": "..." },
  "signals": [ { "severity": "medium", "title": "...", "detail": "..." } ],
  "intel": { "dns": {}, "rdap": {}, "tls": {}, "http": {}, "ct": [], "wellknown": {} },
  "failures": { "ct": "crt.sh timed out ..." }
}
```

The `reports/` folder is in `.gitignore`, so client data is never committed
by accident.

---

## Troubleshooting

| Problem                                    | Fix                                                               |
|--------------------------------------------|-------------------------------------------------------------------|
| `specter` is not recognized                | activate the virtual environment, or run `python -m specter`      |
| CT-LOGS fails or times out                 | crt.sh is overloaded. Run the sweep again in a few minutes        |
| RDAP says "no RDAP record found"           | the TLD does not offer RDAP. Use a normal WHOIS tool for it       |
| DNS says NXDOMAIN                          | check the spelling. The domain does not exist                     |
| TLS fails with `CERTIFICATE_VERIFY_FAILED` | that is a real finding, shown as a HIGH signal                    |
| Banner looks broken or shows `?`           | use Windows Terminal or another UTF-8 terminal with a modern font |
| Colours look wrong                         | use a dark terminal theme with true colour support                |
| "is not a valid domain name"               | SPECTER takes domains only, not IP addresses                      |

---

## Project layout

```
Specter/
  pyproject.toml     package metadata, dependencies, `specter` command
  README.md          this file
  specter/
    __init__.py      version and author
    __main__.py      command-line entry point (argparse)
    app.py           Textual UI, scope gate, scan orchestration, renderers
    recon.py         the six recon modules and input normalization
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

## Disclaimer

SPECTER is for authorized security testing and education. You are
responsible for having permission before scanning any domain. The author
accepts no liability for misuse.

**Made by CyberRaavan**
