<div align="center">

```
  ░██████   ░██                          ░██                              ░█████████                ░██    ░██        
 ░██   ░██  ░██                          ░██                              ░██     ░██               ░██    ░██        
░██         ░████████   ░██████    ░████████  ░███████  ░██    ░██    ░██ ░██     ░██  ░██████   ░████████ ░████████  
 ░████████  ░██    ░██       ░██  ░██    ░██ ░██    ░██ ░██    ░██    ░██ ░█████████        ░██     ░██    ░██    ░██ 
        ░██ ░██    ░██  ░███████  ░██    ░██ ░██    ░██  ░██  ░████  ░██  ░██          ░███████     ░██    ░██    ░██ 
 ░██   ░██  ░██    ░██ ░██   ░██  ░██   ░███ ░██    ░██   ░██░██ ░██░██   ░██         ░██   ░██     ░██    ░██    ░██ 
  ░██████   ░██    ░██  ░█████░██  ░█████░██  ░███████     ░███   ░███    ░██          ░█████░██     ░████ ░██    ░██ 
```

**Hidden Endpoint Discovery Engine**

*Reconnaissance for pentest & bug bounty — subdomain enumeration, endpoint discovery, passive URL harvesting, and SPA-aware crawling with a stealth layer.*

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Version](https://img.shields.io/badge/version-2.2.0-orange.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Why ShadowPath?](#why-shadowpath)
- [Key Features](#key-features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Stealth Timing](#stealth-timing)
- [Output](#output)
- [Configuration](#configuration)
- [FAQ](#faq)
- [Legal & Ethics](#legal--ethics)
- [Contributing](#contributing)

---

## Overview

ShadowPath combines several reconnaissance techniques in a single tool with structured output and a built-in stealth layer. Five operating modes cover everything from passive intelligence gathering to active, JavaScript-rendered reconnaissance.

| Mode | Source | Impact |
|------|--------|--------|
| **OSINT** | GitHub · GitLab · Bitbucket source code | Zero traffic to target |
| **Harvest** | Wayback · Common Crawl · OTX · URLScan | Zero traffic (passive archives) |
| **Crawl** | Real-time web spider (HTML + JS + SPA) | Minimal — browser-like |
| **Active** | Wordlist brute force | Medium — dictionary-based requests |
| **Recon** | Subdomain enum + crawl per subdomain | High — thousands of requests across subdomains |

---

## Why ShadowPath?

Most discovery tools just dump a raw list of URLs — you get thousands of lines with no idea which ones matter. ShadowPath differs in three ways:

- **Classified results, not a raw dump.** Every endpoint is grouped by nature (sensitive/public) and accessibility (open/closed), so you immediately know what to check first.
- **Multi-source in one tool.** Passive archives, live crawl, subdomain enum, and source-code intelligence — no need to chain five separate tools by hand.
- **Context-aware.** It doesn't blindly flag `login` as sensitive; public paths like `portal-belajar` or student logins are recognized as public, reducing false positives.

---

## Key Features

- **Passive URL harvesting** — collect thousands of historical URLs from the Wayback Machine, Common Crawl, AlienVault OTX, and URLScan without touching the target
- **Multi-source subdomain enumeration** — crt.sh, OTX, HackerTarget, Wayback, DNS bruteforce, permutation
- **SPA-aware crawler** — auto-render JavaScript pages (React/Vue/Angular) via headless Chromium; extract links + API endpoints (XHR/fetch)
- **Liveness verification** — DNS + HTTP probe, parking page & soft-error detection (503 behind a 200 status)
- **Stealth layer** — UA rotation, Gaussian timing jitter, header mimicry, noise interleaving
- **4-way endpoint classification** — separates nature (public/private) × accessibility (open/closed), with context-aware keyword matching
- **HTTP status codes** — status codes (200/403/404/…) shown in endpoints.txt and the HTML report, with colored badges
- **Tech fingerprint** — detects server, framework, CMS, JS library, CDN, WAF, analytics
- **Parameter extraction** — query, form, JSON keys, sensitive param detection
- **Interactive HTML report** — searchable, filterable, dark theme, per-scan archive (no overwrites)
- **Notifications** — Discord & Telegram webhooks

---

## Installation

### Quick Start

```bash
git clone https://github.com/hehe986/ShadowPath
cd ShadowPath
pip install -r requirements.txt
```

Requires **Python 3.10+** and **git**.

### SPA Rendering (optional)

To scan SPA websites (React/Vue/Angular), install a headless browser:

```bash
pip install playwright
playwright install chromium
```

Without this, the scanner still runs normally (HTTP mode) — it just can't render SPAs.

### Per Platform

<details>
<summary><b>Debian · Ubuntu · Kali · Parrot · Mint</b></summary>

```bash
sudo apt update
sudo apt install -y python3 python3-pip git
git clone https://github.com/hehe986/ShadowPath
cd ShadowPath
pip3 install -r requirements.txt
```

</details>

<details>
<summary><b>Fedora · RHEL · CentOS · Rocky · AlmaLinux</b></summary>

```bash
sudo dnf install -y python3 python3-pip git
git clone https://github.com/hehe986/ShadowPath
cd ShadowPath
pip3 install -r requirements.txt
```

</details>

<details>
<summary><b>Arch · Manjaro · BlackArch</b></summary>

```bash
sudo pacman -S --needed python python-pip git
git clone https://github.com/hehe986/ShadowPath
cd ShadowPath
pip install -r requirements.txt --break-system-packages
```

</details>

<details>
<summary><b>Windows</b></summary>

Install [Python 3.10+](https://python.org/downloads) (check **Add Python to PATH**) and [Git](https://git-scm.com/download/win).

```powershell
git clone https://github.com/hehe986/ShadowPath
cd ShadowPath
python -m pip install -r requirements.txt
```

</details>

<details>
<summary><b>macOS</b></summary>

```bash
brew install python3 git
git clone https://github.com/hehe986/ShadowPath
cd ShadowPath
pip3 install -r requirements.txt
```

</details>

### Troubleshooting

If you hit an `externally-managed-environment` error (Ubuntu 23.04+, Arch, Alpine):

```bash
pip install -r requirements.txt --break-system-packages
```

---

## Quick Start

First time? Try these three steps against a legal practice target (`testphp.vulnweb.com` by Acunetix):

```bash
# 1. Quick crawl — see linked endpoints
python3 main.py -d testphp.vulnweb.com --crawl --max-pages 5 --timing fast

# 2. Harvest — collect historical URLs from public archives
python3 main.py -d testphp.vulnweb.com --harvest --raw

# 3. Open the interactive report
#   Linux/macOS: xdg-open results/report.html
#   Windows    : start results\report.html
```

---

## Usage

### Harvest Mode — Passive URL Discovery

Collect historical URLs from public archives without touching the target. Can yield thousands of URLs, including old endpoints no longer linked.

```bash
python3 main.py -d target.com --harvest              # classified (grouped)
python3 main.py -d target.com --harvest --raw        # all URLs, no filter
python3 main.py -d target.com --harvest --no-subs    # main domain only
python3 main.py -d target.com --harvest --max-urls 10000
python3 main.py -d target.com --harvest --verify     # check HTTP status of each URL (semi-active)
```

> **Note:** `--verify` contacts the target directly to check each URL's status, so it's no longer purely passive. Without `--verify`, the status column in the report shows `-` (not checked).

### Recon Mode — Full Reconnaissance

Enumerate subdomains from passive sources + DNS bruteforce + permutation, verify liveness, crawl each subdomain, and classify all endpoints.

```bash
python3 main.py -d target.com --recon
python3 main.py -d target.com --recon --max-subs 1000 --pages-per-sub 30
python3 main.py -d target.com --recon --no-crawl              # subdomain list only
python3 main.py -d target.com --recon --skip-empty --timing slow
```

### Crawl Mode — Real-Time Spider

Spider the target application directly, extracting endpoints from HTML and JavaScript. Auto-renders SPAs when detected.

```bash
python3 main.py -d target.com --crawl
python3 main.py -d target.com --crawl --timing slow --max-pages 200
python3 main.py -d target.com --crawl --spa on               # force browser render
python3 main.py -d target.com --crawl --seed https://app.target.com/dashboard
```

The `--spa` option has three values: `off` (HTTP only, fastest), `auto` (render when an SPA is detected — default), and `on` (always use the browser).

### OSINT Mode — Source Code Intelligence

Find endpoints leaked in public source code. No traffic to the target.

```bash
python3 main.py -d target.com
python3 main.py -d target.com -k <github_token>
python3 main.py -d target.com --sources github,gitlab
python3 main.py -d target.com --deep
```

### Active Mode — Wordlist Brute Force

Discover endpoints via a dictionary attack. The Closed categories (403/404) fill up most in this mode.

```bash
python3 main.py -d target.com --active
python3 main.py -d target.com --active --wordlist custom.txt --threads 20
```

Run `python3 main.py --help` for all options.

---

## Stealth Timing

Timing mode sets the delay between requests using a Gaussian distribution to mimic human browsing patterns.

| Mode | Delay | Use Case |
|------|-------|----------|
| `fast` | 0.3 – 1.5s | Aggressive scan, lab/CTF |
| `normal` | 1.0 – 4.0s | Default — balances speed & stealth |
| `slow` | 3.0 – 8.0s | Maximum stealth for production targets |
| `random` | Mix | Most natural distribution |

Set the default via `STEALTH_TIMING` in `config.py`, or override with `--timing`.

---

## Output

Scan results are saved automatically in the `results/` directory:

| File | Contents |
|------|----------|
| `endpoints.txt` | Endpoints split by category, with status codes |
| `subdomains.txt` | Subdomain list by liveness status |
| `parameters.txt` | Parameters (sensitive + regular) |
| `harvested_urls.txt` | URLs from harvest mode |
| `report.html` | Interactive report (searchable, filterable) + per-scan archive |
| `scan_results.json` / `recon_results.json` | Full data for parsing |

### Endpoint Classification

Endpoints are classified along two dimensions: **nature** (contains sensitive keywords) and **accessibility** (HTTP status response).

| Category | Condition | Priority |
|----------|-----------|----------|
| `PRIVATE-OPEN` | Sensitive endpoint with status 200 | **High** — potential critical finding |
| `PUBLIC-OPEN` | Public endpoint, accessible | Normal |
| `PRIVATE-CLOSED` | Sensitive endpoint with status 401/403 | Medium — auth-gated |
| `PUBLIC-CLOSED` | Public endpoint with status 404 | Low — reference |

Keyword matching is context-aware: public paths like `portal-belajar`, `e-learning`, or common-user logins (student/parent/alumni) are not mislabeled as private. Admin/staff logins remain classified as private.

### HTTP Status Codes

The report shows each endpoint's status code with a colored badge:

| Color | Range | Meaning |
|-------|-------|---------|
| 🟢 Green | 2xx | Success / accessible |
| 🔵 Blue | 3xx | Redirect |
| 🟡 Yellow | 401, 403 | Auth required / forbidden |
| 🔴 Red | 4xx, 5xx | Client / server error |

### Subdomain Liveness Status

| Status | Condition |
|--------|-----------|
| `LIVE` | DNS resolves, HTTP responsive, application content detected |
| `REACHABLE_EMPTY` | HTTP responds but parking page / default landing |
| `DNS_ONLY` | DNS resolves but HTTP not responsive |
| `DEAD` | DNS does not resolve |

---

## Configuration

All defaults can be overridden via `config.py`. Main settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `STEALTH_TIMING` | `"normal"` | Default timing mode |
| `SPA_MODE` | `"auto"` | SPA rendering: off / auto / on |
| `CRAWL_MAX_PAGES` | `100` | Crawl limit per session |
| `RECON_MAX_SUBS` | `500` | Subdomain enumeration limit |
| `THREADS` | `10` | Parallel workers for active scan |
| `GITHUB_TOKEN` | `""` | Token to raise OSINT rate limit |
| `DISCORD_WEBHOOK_URL` | `""` | Discord notification webhook |

---

## FAQ

**Why does harvest sometimes return thousands of URLs and sometimes just a few?**
The largest archive source (Wayback Machine) is sometimes slow or times out. When that happens, the URL count drops sharply because only the other sources are collected. ShadowPath already applies automatic retries; you can also lighten the query load with `--max-urls`.

**My HTML report is empty / the target shows "Unknown", why?**
Usually because you opened a `report.html` from an old scan that was overwritten by a newer one, or the target is an SPA that wasn't rendered. Check the report header (`Generated:`) for the timestamp, and use the archived `report_<target>_<time>.html` file.

**The endpoint status shows `-` in harvest mode, is that a bug?**
No. Harvest is passive — URLs come from archives without any request to the target, so the HTTP status is unknown. Add `--verify` if you want to check the status (this makes it semi-active).

**My SPA returns no links (URLs found: 0) even though the page size is large.**
That's the hallmark of an SPA: the raw HTML is empty and content is rendered by JavaScript. Run with `--spa on` and make sure Playwright + Chromium are installed.

---

## Legal & Ethics

> **Use only on targets you have explicit permission to test.**

Legal usage categories:

- Local labs or your own virtual machines
- CTF platforms (HackTheBox, TryHackMe, PortSwigger Academy)
- Bug bounty programs — **must be in-scope**, check scope on HackerOne/Bugcrowd/Intigriti
- Pentest engagements with written client authorization

For safe practice, official legal targets by Acunetix are available: `testphp.vulnweb.com`, `testasp.vulnweb.com`, `testaspnet.vulnweb.com`, and `testhtml5.vulnweb.com`.

**Note on Recon & Harvest modes:** both can generate a large volume of requests or data. Although Harvest is passive (pulling from third-party archives), make sure your reconnaissance activity against a target stays within an authorized scope.

Unauthorized use is illegal in many countries. In Indonesia, it violates **Law ITE Article 30**, carrying up to 8 years imprisonment and fines up to IDR 800 million.

### Disclaimer

This tool is provided "as is". The author is not responsible for any actions taken by users. All risk and responsibility lie entirely with the user.

---

## Contributing

Contributions welcome. For major changes, open an issue first to discuss.

General flow: fork the repo → create a feature branch (`git checkout -b new-feature`) → commit your changes → push → open a Pull Request.

---

<div align="center">

**MIT License** © 2026 H1lm1.exe

</div>
