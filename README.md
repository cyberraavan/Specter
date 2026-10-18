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

A passive recon console for the first hours of an **authorized** red team
engagement. Give it a domain and it sweeps six intel sources at once, then
turns the raw output into ranked **signals**: the things worth looking at first.

## Authorized use only

Only point SPECTER at domains that are inside a written engagement scope.
Every new target goes through a rules-of-engagement prompt before anything
is sent.

SPECTER is low-touch by design:

| Module     | Talks to                 | What it does                                  |
|------------|--------------------------|-----------------------------------------------|
| DNS        | your resolver            | A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, DMARC  |
| RDAP       | rdap.org (registries)    | registrar, dates, status, nameservers, DNSSEC |
| CT-LOGS    | crt.sh                   | hostnames from certificate transparency logs  |
| TLS        | target, port 443         | one handshake: issuer, expiry, SANs, protocol |
| HTTP       | target                   | one GET of `/`: headers, title, tech hints    |
| WELL-KNOWN | target                   | GET `security.txt` and `robots.txt`           |

There is no port scanning, brute forcing, fuzzing, or exploitation. The
target sees about what it would see from one browser visit.

## Signals

The SIGNALS tab ranks findings as HIGH / MEDIUM / LOW / INFO:

- **Email spoofing posture**: missing or weak SPF (`+all`, `?all`, `~all`), missing DMARC, `p=none`
- **TLS**: certificate fails verification, has expired, or expires soon
- **HTTP hardening**: no HSTS, missing security headers, plain HTTP
- **Information leaks**: versioned `Server` banners, `X-Powered-By`
- **Attack surface**: hostnames in CT logs such as `dev`, `staging`, `vpn`, `jenkins`, `admin` (shown in red in the CT-LOGS tab)
- **Context**: tech fingerprint, robots.txt disallowed paths, security.txt contacts, domain expiry, DNSSEC

## Install and run

Requires Python 3.10+.

```sh
pip install -e .
specter                 # or: python -m specter
specter example.com     # prefill the target
```

| Key      | Action                                          |
|----------|-------------------------------------------------|
| `Enter`  | run the sweep on the target in the input        |
| `Ctrl+S` | save the report to `reports/` (Markdown + JSON) |
| `Ctrl+L` | clear the ops log                               |
| `Ctrl+Q` | quit                                            |

For the full effect, use a terminal with a dark background and a font
that has box-drawing characters (Windows Terminal, Cascadia Mono).

## Notes

- crt.sh is a free public service that is often overloaded. SPECTER retries
  it 3 times; if CT-LOGS still fails, run the sweep again later.
- Reports are written to `reports/` in the current directory, which is git-ignored.

## Layout

```
specter/
  app.py        Textual UI, scope gate, scan orchestration
  recon.py      the six recon modules
  signals.py    rules that turn raw intel into ranked findings
  report.py     Markdown and JSON export
  specter.tcss  the theme
```
