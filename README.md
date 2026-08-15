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

*Reconnaissance untuk pentest & bug bounty — subdomain enum, endpoint discovery, dan real-time crawling.*

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Version](https://img.shields.io/badge/version-1.6.0-orange.svg)

</div>

---

## Overview

Empat mode operasi untuk kebutuhan recon berbeda:

| Mode | Fungsi |
|------|--------|
| **OSINT** | Cari endpoint dari source code publik (GitHub/GitLab/Bitbucket) |
| **Crawl** | Real-time web spider dengan stealth layer |
| **Active** | Wordlist brute force |
| **Recon** | Full: subdomain enum → crawl per subdomain → classify |

---

## Install

```bash
git clone https://github.com/hehe986/ShadowPath
cd ShadowPath
pip install -r requirements.txt
```

Requires Python 3.10+.

---

## Usage

```bash
# Full recon (subdomain + endpoint)
python3 main.py -d target.com --recon

# Real-time crawler
python3 main.py -d target.com --crawl

# OSINT dari GitHub
python3 main.py -d target.com -k <github_token>

# Wordlist scan
python3 main.py -d target.com --active
```

Lihat `--help` untuk semua opsi.

---

## Output

Hasil tersimpan di `results/`:

| File | Isi |
|------|-----|
| `endpoints.txt` | Endpoint per kategori |
| `subdomains.txt` | Subdomain per status liveness |
| `parameters.txt` | Parameter yang ditemukan |
| `*.json` | Full data untuk parsing programmatic |

**Endpoint diklasifikasi 4-way:** `PRIVATE-OPEN` (prioritas tinggi) · `PUBLIC-OPEN` · `PRIVATE-CLOSED` · `PUBLIC-CLOSED`

---

## Stealth Timing

| Mode | Delay | Use Case |
|------|-------|----------|
| `fast` | 0.3–1.5s | Aggressive |
| `normal` | 1.0–4.0s | Recommended |
| `slow` | 3.0–8.0s | Maximum stealth |
| `random` | mix | Distribusi natural |

---

## Legal

Gunakan hanya pada target dengan izin eksplisit — lab sendiri, CTF, bug bounty in-scope, atau pentest engagement authorized.

Penggunaan tanpa izin melanggar **UU ITE Pasal 30**. Author tidak bertanggung jawab atas penyalahgunaan.

---

<div align="center">

MIT © H1lm1.exe

</div>
