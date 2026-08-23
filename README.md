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

*Reconnaissance untuk pentest & bug bounty — subdomain enumeration, endpoint discovery, passive URL harvesting, dan SPA-aware crawling dengan stealth layer.*

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Version](https://img.shields.io/badge/version-2.2.0-orange.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)

</div>

---

## Daftar Isi

- [Overview](#overview)
- [Kenapa ShadowPath?](#kenapa-shadowpath)
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

ShadowPath menggabungkan beberapa teknik reconnaissance dalam satu tool dengan output terstruktur dan stealth layer built-in. Lima mode operasi mencakup kebutuhan dari passive intelligence gathering sampai active reconnaissance ber-render JavaScript.

| Mode | Sumber | Impact |
|------|--------|--------|
| **OSINT** | GitHub · GitLab · Bitbucket source code | Zero traffic ke target |
| **Harvest** | Wayback · Common Crawl · OTX · URLScan | Zero traffic (arsip pasif) |
| **Crawl** | Real-time web spider (HTML + JS + SPA) | Minimal — mirip browser |
| **Active** | Wordlist brute force | Medium — request berbasis dictionary |
| **Recon** | Subdomain enum + crawl per subdomain | Tinggi — ribuan request lintas subdomain |

---

## Kenapa ShadowPath?

Kebanyakan tool discovery hanya memuntahkan daftar URL mentah — kamu dapat ribuan baris tanpa tahu mana yang penting. ShadowPath berbeda pada tiga hal:

- **Hasil terklasifikasi, bukan daftar mentah.** Setiap endpoint dikelompokkan berdasarkan sifat (sensitif/umum) dan aksesibilitas (terbuka/terkunci), jadi kamu langsung tahu mana yang layak diperiksa duluan.
- **Multi-sumber dalam satu tool.** Passive archive, live crawl, subdomain enum, dan source-code intelligence — tidak perlu merangkai lima tool berbeda secara manual.
- **Context-aware.** Tidak asal menandai `login` sebagai sensitif; path publik seperti `portal-belajar` atau login siswa dikenali sebagai umum, mengurangi false positive.

---

## Key Features

- **Passive URL harvesting** — kumpulkan ribuan URL historis dari Wayback Machine, Common Crawl, AlienVault OTX, dan URLScan tanpa menyentuh target
- **Multi-source subdomain enumeration** — crt.sh, OTX, HackerTarget, Wayback, DNS bruteforce, permutation
- **SPA-aware crawler** — auto-render halaman JavaScript (React/Vue/Angular) via headless Chromium; extract link + API endpoint (XHR/fetch)
- **Liveness verification** — DNS + HTTP probe, deteksi parking page & soft-error (503 di balik status 200)
- **Stealth layer** — UA rotation, Gaussian timing jitter, header mimicry, noise interleaving
- **4-way endpoint classification** — memisahkan sifat (public/private) × aksesibilitas (open/closed), dengan context-aware keyword matching
- **HTTP status code** — kode status (200/403/404/…) ditampilkan di endpoints.txt dan report HTML, dengan badge berwarna
- **Tech fingerprint** — deteksi server, framework, CMS, JS library, CDN, WAF, analytics
- **Parameter extraction** — query, form, JSON keys, sensitive param detection
- **Interactive HTML report** — searchable, filterable, dark theme, arsip per-scan (tidak saling menimpa)
- **Notifikasi** — Discord & Telegram webhook

---

## Installation

### Quick Start

```bash
git clone https://github.com/hehe986/ShadowPath
cd ShadowPath
pip install -r requirements.txt
```

Requires **Python 3.10+** dan **git**.

### SPA Rendering (opsional)

Untuk scan website SPA (React/Vue/Angular), install headless browser:

```bash
pip install playwright
playwright install chromium
```

Tanpa ini, scanner tetap jalan normal (HTTP mode) — hanya tidak bisa render SPA.

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

Jika muncul error `externally-managed-environment` (Ubuntu 23.04+, Arch, Alpine):

```bash
pip install -r requirements.txt --break-system-packages
```

---

## Quick Start

Baru pertama kali? Coba tiga langkah ini di target latihan legal (`testphp.vulnweb.com` milik Acunetix):

```bash
# 1. Crawl cepat — lihat endpoint yang ter-link
python3 main.py -d testphp.vulnweb.com --crawl --max-pages 5 --timing fast

# 2. Harvest — kumpulkan URL historis dari arsip publik
python3 main.py -d testphp.vulnweb.com --harvest --raw

# 3. Buka laporan interaktif
#   Linux/macOS: xdg-open results/report.html
#   Windows    : start results\report.html
```

---

## Usage

### Harvest Mode — Passive URL Discovery

Kumpulkan URL historis dari arsip publik tanpa menyentuh target. Bisa menghasilkan ribuan URL termasuk endpoint lama yang sudah tidak ter-link.

```bash
python3 main.py -d target.com --harvest              # classified (dikelompokkan)
python3 main.py -d target.com --harvest --raw        # semua URL tanpa filter
python3 main.py -d target.com --harvest --no-subs    # domain utama saja
python3 main.py -d target.com --harvest --max-urls 10000
python3 main.py -d target.com --harvest --verify     # cek status HTTP tiap URL (semi-aktif)
```

> **Catatan:** `--verify` menghubungi target langsung untuk mengecek status tiap URL, sehingga tidak lagi murni pasif. Tanpa `--verify`, kolom status di laporan tampil sebagai `-` (belum dicek).

### Recon Mode — Full Reconnaissance

Enumerate subdomain dari sumber passive + DNS bruteforce + permutation, verifikasi liveness, crawl setiap subdomain, dan classify semua endpoint.

```bash
python3 main.py -d target.com --recon
python3 main.py -d target.com --recon --max-subs 1000 --pages-per-sub 30
python3 main.py -d target.com --recon --no-crawl              # subdomain list saja
python3 main.py -d target.com --recon --skip-empty --timing slow
```

### Crawl Mode — Real-Time Spider

Spider langsung ke aplikasi target, extract endpoint dari HTML dan JavaScript. Auto-render SPA bila terdeteksi.

```bash
python3 main.py -d target.com --crawl
python3 main.py -d target.com --crawl --timing slow --max-pages 200
python3 main.py -d target.com --crawl --spa on               # paksa browser render
python3 main.py -d target.com --crawl --seed https://app.target.com/dashboard
```

Opsi `--spa` punya tiga nilai: `off` (HTTP saja, tercepat), `auto` (render bila terdeteksi SPA — default), dan `on` (selalu pakai browser).

### OSINT Mode — Source Code Intelligence

Cari endpoint yang bocor di source code publik. Tanpa traffic ke target.

```bash
python3 main.py -d target.com
python3 main.py -d target.com -k <github_token>
python3 main.py -d target.com --sources github,gitlab
python3 main.py -d target.com --deep
```

### Active Mode — Wordlist Brute Force

Discovery endpoint via dictionary attack. Kategori Closed (403/404) paling banyak terisi di mode ini.

```bash
python3 main.py -d target.com --active
python3 main.py -d target.com --active --wordlist custom.txt --threads 20
```

Lihat `python3 main.py --help` untuk semua opsi.

---

## Stealth Timing

Timing mode mengatur delay antar request dengan Gaussian distribution untuk meniru pola browsing manusia.

| Mode | Delay | Use Case |
|------|-------|----------|
| `fast` | 0.3 – 1.5s | Aggressive scan, lab/CTF |
| `normal` | 1.0 – 4.0s | Default — balance kecepatan & stealth |
| `slow` | 3.0 – 8.0s | Maximum stealth untuk target production |
| `random` | Mix | Distribusi paling natural |

Set default via `STEALTH_TIMING` di `config.py`, atau override dengan `--timing`.

---

## Output

Hasil scan tersimpan otomatis di direktori `results/`:

| File | Isi |
|------|-----|
| `endpoints.txt` | Endpoint terpisah per kategori, dengan kode status |
| `subdomains.txt` | Subdomain list per status liveness |
| `parameters.txt` | Parameter (sensitive + regular) |
| `harvested_urls.txt` | URL hasil harvest mode |
| `report.html` | Report interaktif (searchable, filterable) + arsip per-scan |
| `scan_results.json` / `recon_results.json` | Full data untuk parsing |

### Endpoint Classification

Endpoint diklasifikasi berdasarkan dua dimensi: **sifat** (mengandung keyword sensitif) dan **aksesibilitas** (HTTP status response).

| Kategori | Kondisi | Prioritas |
|----------|---------|-----------|
| `PRIVATE-OPEN` | Endpoint sensitif dengan status 200 | **Tinggi** — potensial critical finding |
| `PUBLIC-OPEN` | Endpoint umum accessible | Normal |
| `PRIVATE-CLOSED` | Endpoint sensitif dengan status 401/403 | Medium — auth-gated |
| `PUBLIC-CLOSED` | Endpoint umum dengan status 404 | Rendah — reference |

Keyword matching bersifat context-aware: path publik seperti `portal-belajar`, `e-learning`, atau login role user umum (siswa/ortu/alumni) tidak salah diklasifikasi sebagai private. Login admin/guru tetap dikelompokkan private.

### HTTP Status Code

Laporan menampilkan kode status tiap endpoint dengan badge berwarna:

| Warna | Range | Arti |
|-------|-------|------|
| 🟢 Hijau | 2xx | Sukses / accessible |
| 🔵 Biru | 3xx | Redirect |
| 🟡 Kuning | 401, 403 | Butuh autentikasi / forbidden |
| 🔴 Merah | 4xx, 5xx | Client / server error |

### Subdomain Liveness Status

| Status | Kondisi |
|--------|---------|
| `LIVE` | DNS resolve, HTTP responsif, konten aplikasi terdeteksi |
| `REACHABLE_EMPTY` | HTTP respond tapi parking page / default landing |
| `DNS_ONLY` | DNS resolve tapi HTTP tidak responsif |
| `DEAD` | DNS tidak resolve |

---

## Configuration

Semua default dapat di-override via `config.py`. Setting utama:

| Variable | Default | Deskripsi |
|----------|---------|-----------|
| `STEALTH_TIMING` | `"normal"` | Default timing mode |
| `SPA_MODE` | `"auto"` | Rendering SPA: off / auto / on |
| `CRAWL_MAX_PAGES` | `100` | Batas crawl per session |
| `RECON_MAX_SUBS` | `500` | Batas enumerasi subdomain |
| `THREADS` | `10` | Paralel worker active scan |
| `GITHUB_TOKEN` | `""` | Token untuk raise rate limit OSINT |
| `DISCORD_WEBHOOK_URL` | `""` | Webhook notifikasi Discord |

---

## FAQ

**Kenapa hasil harvest kadang ribuan, kadang cuma puluhan?**
Sumber arsip terbesar (Wayback Machine) kadang lambat atau timeout. Saat itu terjadi, jumlah URL turun drastis karena hanya sumber lain yang terkumpul. ShadowPath sudah menerapkan retry otomatis; kamu juga bisa memperkecil beban query dengan `--max-urls`.

**Report HTML saya kosong / target-nya "Unknown", kenapa?**
Biasanya karena membuka `report.html` dari scan lama yang sudah tertimpa scan baru, atau target adalah SPA yang tidak dirender. Cek header laporan (`Generated:`) untuk memastikan waktunya, dan gunakan file arsip `report_<target>_<waktu>.html`.

**Kolom status endpoint tampil `-` di mode harvest, apakah bug?**
Bukan. Harvest bersifat pasif — URL diambil dari arsip tanpa request ke target, jadi status HTTP belum diketahui. Tambahkan `--verify` bila ingin mengecek status (menjadi semi-aktif).

**SPA saya tidak menghasilkan link (URLs found: 0) padahal ukuran halaman besar.**
Itu ciri SPA: HTML mentah kosong, konten dirender JavaScript. Jalankan dengan `--spa on` dan pastikan Playwright + Chromium sudah terpasang.

---

## Legal & Ethics

> **Gunakan hanya pada target dengan izin eksplisit.**

Kategori penggunaan legal:

- Lab lokal atau virtual machine milik sendiri
- Platform CTF (HackTheBox, TryHackMe, PortSwigger Academy)
- Program bug bounty — **wajib in-scope**, cek scope di HackerOne/Bugcrowd/Intigriti
- Pentest engagement dengan authorization tertulis dari klien

Untuk latihan aman, tersedia target legal resmi milik Acunetix: `testphp.vulnweb.com`, `testasp.vulnweb.com`, `testaspnet.vulnweb.com`, dan `testhtml5.vulnweb.com`.

**Perhatian untuk Recon & Harvest Mode:** kedua mode ini dapat menghasilkan volume request atau data yang besar. Meskipun Harvest bersifat pasif (mengambil dari arsip pihak ketiga), tetap pastikan aktivitas reconnaissance-mu terhadap suatu target berada dalam ruang lingkup yang diizinkan.

Penggunaan tanpa izin melanggar hukum di banyak negara. Di Indonesia, melanggar **UU ITE Pasal 30** dengan ancaman pidana penjara hingga 8 tahun dan denda hingga 800 juta rupiah. Author tidak bertanggung jawab atas penyalahgunaan tool ini.

---

## Contributing

Contributions welcome. Untuk perubahan besar, buka issue terlebih dahulu untuk diskusi.

Langkah umum: fork repo → buat branch fitur (`git checkout -b fitur-baru`) → commit perubahan → push → buka Pull Request.

---

<div align="center">

**MIT License** © 2026 H1lm1.exe

</div>
