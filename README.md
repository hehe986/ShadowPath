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

*Reconnaissance untuk pentest & bug bounty — subdomain enumeration, endpoint discovery, dan real-time crawling dengan stealth layer.*

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Version](https://img.shields.io/badge/version-1.6.0-orange.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)

</div>

---

## Overview

ShadowPath menggabungkan multiple recon technique dalam satu tool dengan output terstruktur dan stealth layer built-in. Empat mode operasi mencakup kebutuhan dari passive intelligence gathering sampai full active reconnaissance.

| Mode | Sumber | Impact |
|------|--------|--------|
| **OSINT** | GitHub · GitLab · Bitbucket source code | Zero traffic ke target |
| **Crawl** | Real-time web spider (HTML + JS) | Minimal — mirip browser |
| **Active** | Wordlist brute force | Medium — request berbasis dictionary |
| **Recon** | Subdomain enum + crawl per subdomain | Tinggi — ribuan request lintas subdomain |

---

## Key Features

- **Multi-source subdomain enumeration** — crt.sh, AlienVault OTX, HackerTarget, Wayback Machine, DNS bruteforce, permutation engine
- **Liveness verification** — DNS resolution + HTTP probe, deteksi parking page & default landing
- **Real-time crawler** — HTML parser + inline JS + external JS files
- **Stealth layer** — UA rotation, Gaussian timing jitter, header mimicry, noise interleaving
- **4-way endpoint classification** — memisahkan sifat (public/private) × aksesibilitas (open/closed)
- **Parameter extraction** — query string, form fields, JSON keys, sensitive param detection
- **Duplicate response filter** — fingerprint + similarity ratio untuk buang soft 404

---

## Installation

### Quick Start

```bash
git clone https://github.com/hehe986/ShadowPath
cd ShadowPath
pip install -r requirements.txt
```

Requires **Python 3.10+** dan **git**.

### Per Platform

<details>
<summary><b>Debian · Ubuntu · Kali · Parrot · Mint · Pop!_OS</b></summary>

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
<summary><b>Arch · Manjaro · EndeavourOS · BlackArch</b></summary>

```bash
sudo pacman -S --needed python python-pip git
git clone https://github.com/hehe986/ShadowPath
cd ShadowPath
pip install -r requirements.txt --break-system-packages
```

</details>

<details>
<summary><b>Alpine · openSUSE · Void · Gentoo · NixOS</b></summary>

Install `python3`, `pip`, dan `git` via package manager masing-masing distro, lalu:

```bash
git clone https://github.com/hehe986/ShadowPath
cd ShadowPath
pip install -r requirements.txt --break-system-packages
```

</details>

<details>
<summary><b>Windows</b></summary>

Install [Python 3.10+](https://python.org/downloads) (centang **Add Python to PATH**) dan [Git](https://git-scm.com/download/win).

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

Jika muncul error `externally-managed-environment` pada distro modern (Ubuntu 23.04+, Arch, Alpine), tambahkan flag berikut:

```bash
pip install -r requirements.txt --break-system-packages
```

Alternatif — gunakan virtual environment untuk isolasi:

```bash
python3 -m venv .venv
source .venv/bin/activate     # Linux · macOS
# .venv\Scripts\activate      # Windows
pip install -r requirements.txt
```

---

## Usage

### Recon Mode — Full Reconnaissance

Enumerate subdomain dari 4 sumber passive + DNS bruteforce + permutation, verifikasi liveness, crawl setiap subdomain, dan classify semua endpoint yang ditemukan.

```bash
python3 main.py -d target.com --recon
python3 main.py -d target.com --recon --max-subs 1000 --pages-per-sub 30
python3 main.py -d target.com --recon --no-bruteforce            # passive only
python3 main.py -d target.com --recon --no-crawl                 # subdomain list only
python3 main.py -d target.com --recon --skip-empty --timing slow # skip parking, maximum stealth
```

### Crawl Mode — Real-Time Spider

Spider langsung ke aplikasi target, extract endpoint dari HTML dan JavaScript secara live.

```bash
python3 main.py -d target.com --crawl
python3 main.py -d target.com --crawl --timing slow --max-pages 200
python3 main.py -d target.com --crawl --seed https://app.target.com/dashboard
python3 main.py -d target.com --crawl --follow-subs
```

### OSINT Mode — Source Code Intelligence

Cari endpoint yang bocor di source code publik. Tanpa traffic ke target.

```bash
python3 main.py -d target.com
python3 main.py -d target.com -k <github_token>          # rate limit lebih tinggi
python3 main.py -d target.com --sources github,gitlab
python3 main.py -d target.com --deep                     # scan full repo tree
```

### Active Mode — Wordlist Brute Force

Discovery endpoint via dictionary attack dengan wordlist custom.

```bash
python3 main.py -d target.com --active
python3 main.py -d target.com --active --wordlist custom.txt --threads 20
```

Lihat `python3 main.py --help` untuk semua opsi yang tersedia.

---

## Stealth Timing

Timing mode mengatur delay antar request dengan Gaussian distribution untuk meniru pola browsing manusia.

| Mode | Delay | Use Case |
|------|-------|----------|
| `fast` | 0.3 – 1.5s | Aggressive scan, lab/CTF |
| `normal` | 1.0 – 4.0s | Default — balance kecepatan & stealth |
| `slow` | 3.0 – 8.0s | Maximum stealth untuk target production |
| `random` | Mix | Distribusi paling natural |

Set default via `STEALTH_TIMING` di `config.py`, atau override per-run dengan `--timing`.

---

## Output

Hasil scan tersimpan otomatis di direktori `results/`:

| File | Isi |
|------|-----|
| `endpoints.txt` | Endpoint terpisah per kategori dengan breakdown per subdomain |
| `subdomains.txt` | Subdomain list per status liveness |
| `parameters.txt` | Parameter yang ditemukan (sensitive + regular) |
| `scan_results.json` | Full data (crawl/active/osint mode) |
| `recon_results.json` | Full data recon mode dengan aggregasi |

### Endpoint Classification

Endpoint diklasifikasi berdasarkan dua dimensi: **sifat** (mengandung keyword sensitif seperti `admin`, `auth`, `token`) dan **aksesibilitas** (HTTP status response).

| Kategori | Kondisi | Prioritas |
|----------|---------|-----------|
| `PRIVATE-OPEN` | Endpoint sensitif dengan status 200 | **Tinggi** — potensial critical finding |
| `PUBLIC-OPEN` | Endpoint umum accessible | Normal |
| `PRIVATE-CLOSED` | Endpoint sensitif dengan status 401/403 | Medium — auth-gated, worth investigating |
| `PUBLIC-CLOSED` | Endpoint umum dengan status 404 | Rendah — reference only |

### Subdomain Liveness Status

| Status | Kondisi |
|--------|---------|
| `LIVE` | DNS resolve, HTTP 200-403, konten aplikasi terdeteksi |
| `REACHABLE_EMPTY` | HTTP respond tapi parking page / default landing |
| `DNS_ONLY` | DNS resolve tapi tidak ada HTTP server responsive |
| `DEAD` | DNS tidak resolve |

---

## Configuration

Semua default value dapat di-override via `config.py`. Setting utama:

| Variable | Default | Deskripsi |
|----------|---------|-----------|
| `STEALTH_TIMING` | `"normal"` | Default timing mode |
| `CRAWL_MAX_PAGES` | `100` | Batas crawl per session |
| `RECON_MAX_SUBS` | `500` | Batas enumerasi subdomain |
| `RECON_MAX_PAGES_PER_SUB` | `20` | Crawl budget per subdomain di recon mode |
| `THREADS` | `10` | Paralel worker untuk active scan |
| `SIMILARITY_THRESHOLD` | `0.92` | Threshold soft 404 detection |
| `GITHUB_TOKEN` | `""` | Set token untuk raise rate limit OSINT |

---

## Legal & Ethics

> **Gunakan hanya pada target dengan izin eksplisit.**

Kategori penggunaan legal:

- Lab lokal atau virtual machine milik sendiri
- Platform CTF (HackTheBox, TryHackMe, PortSwigger Academy, dll)
- Program bug bounty — **wajib in-scope**, cek scope program di HackerOne/Bugcrowd/Intigriti
- Pentest engagement dengan authorization tertulis dari klien

**Perhatian untuk Recon Mode:** mode ini menghasilkan ribuan DNS query dan HTTP request lintas subdomain dalam satu run. Volume traffic-nya pasti tercatat di log DNS resolver, target server, dan CDN — bahkan dengan stealth layer aktif. Pastikan target benar-benar authorized sebelum menggunakan mode ini.

Penggunaan tanpa izin melanggar hukum di banyak negara. Di Indonesia, tindakan ini melanggar **UU ITE Pasal 30** dengan ancaman pidana penjara hingga 8 tahun dan denda hingga 800 juta rupiah. Author tidak bertanggung jawab atas penyalahgunaan tool ini.

---

## Contributing

Contributions welcome. Untuk perubahan besar, buka issue terlebih dahulu untuk diskusi.

---

<div align="center">

**MIT License** © 2026 H1lm1.exe

</div>
