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

### **Hidden Endpoint Discovery Engine**

*Reconnaissance tool untuk pentest & bug bounty — menemukan endpoint tersembunyi via OSINT, real-time crawling, dan stealth active scanning.*

---

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)

</div>

---

## ✨ Overview

ShadowPath menemukan endpoint tersembunyi via **3 mode operasi**:

| Mode | Sumber | Use Case |
|------|--------|----------|
| 🔵 **OSINT** | GitHub / GitLab / Bitbucket source code | Recon awal, low-risk (tidak hit target) |
| 🔴 **Active** | Wordlist brute force | Discovery cepat dengan wordlist kustom |
| 🕸️ **Crawl** | Real-time web spider | Discovery akurat dari aplikasi live target |

---

## 🚀 Features

- 🌐 **Multi-source OSINT** — GitHub, GitLab, Bitbucket
- 🕸️ **Real-time crawler** — HTML/JS endpoint extraction
- 🎭 **Stealth layer** — UA rotation, timing jitter, header mimicry
- 🎯 **Liveness verification** — DNS + HTTP probe, deteksi parking page
- 📊 **4-way classification** — public/private × open/closed
- 🔑 **Parameter extraction** — query, form, JSON keys + sensitive detection
- 🧬 **Duplicate detection** — soft 404 filter via fingerprint & similarity
- 📁 **Output** — TXT (per-kategori) + JSON (full data)

---

## 📦 Installation

### Requirements
- Python **3.10+**
- pip
- git

### Linux

<details>
<summary><b>Debian / Ubuntu / Kali / Parrot / Mint / Pop!_OS</b></summary>

```bash
sudo apt update
sudo apt install -y python3 python3-pip git
git clone https://github.com/username/ShadowPath
cd ShadowPath
pip3 install -r requirements.txt
```
</details>

<details>
<summary><b>Fedora / RHEL / CentOS Stream / Rocky / AlmaLinux</b></summary>

```bash
sudo dnf install -y python3 python3-pip git
git clone https://github.com/username/ShadowPath
cd ShadowPath
pip3 install -r requirements.txt
```
</details>

<details>
<summary><b>Arch / Manjaro / EndeavourOS / BlackArch</b></summary>

```bash
sudo pacman -S --needed python python-pip git
git clone https://github.com/username/ShadowPath
cd ShadowPath
pip install -r requirements.txt --break-system-packages
```
</details>

<details>
<summary><b>openSUSE (Leap / Tumbleweed)</b></summary>

```bash
sudo zypper install -y python3 python3-pip git
git clone https://github.com/username/ShadowPath
cd ShadowPath
pip3 install -r requirements.txt
```
</details>

<details>
<summary><b>Alpine</b></summary>

```bash
sudo apk add python3 py3-pip git
git clone https://github.com/username/ShadowPath
cd ShadowPath
pip3 install -r requirements.txt --break-system-packages
```
</details>

<details>
<summary><b>Void Linux</b></summary>

```bash
sudo xbps-install -S python3 python3-pip git
git clone https://github.com/username/ShadowPath
cd ShadowPath
pip3 install -r requirements.txt
```
</details>

<details>
<summary><b>Gentoo</b></summary>

```bash
sudo emerge --ask dev-lang/python dev-python/pip dev-vcs/git
git clone https://github.com/username/ShadowPath
cd ShadowPath
pip install -r requirements.txt
```
</details>

<details>
<summary><b>NixOS</b></summary>

```bash
nix-shell -p python3 python3Packages.pip git
git clone https://github.com/username/ShadowPath
cd ShadowPath
pip install -r requirements.txt
```
</details>

### Windows

```powershell
# Install Python 3.10+ dari python.org (centang "Add to PATH")
git clone https://github.com/username/ShadowPath
cd ShadowPath
python -m pip install -r requirements.txt
```

### macOS

```bash
brew install python3 git
git clone https://github.com/username/ShadowPath
cd ShadowPath
pip3 install -r requirements.txt
```

### Virtual Environment (Recommended)

Kalau mau isolate dependencies dari system Python:

```bash
python3 -m venv .venv
source .venv/bin/activate     # Linux/macOS
# .venv\Scripts\activate       # Windows
pip install -r requirements.txt
```

---

## 🎯 Usage

### Crawl Mode (Recommended)

Real-time spider dengan stealth layer & liveness verification.

```bash
python3 main.py -d target.com --crawl
python3 main.py -d target.com --crawl --timing slow --max-pages 200
python3 main.py -d target.com --crawl --follow-subs
python3 main.py -d target.com --crawl --seed https://app.target.com/dashboard
```

### OSINT Mode

Cari endpoint dari source code publik di GitHub/GitLab/Bitbucket.

```bash
python3 main.py -d target.com
python3 main.py -d target.com -k <github_token>     # rate limit lebih tinggi
python3 main.py -d target.com --deep                # scan full repo tree
python3 main.py -d target.com --sources github,gitlab
```

### Active Mode

Wordlist-based brute force scan.

```bash
python3 main.py -d target.com --active
python3 main.py -d target.com --active --wordlist wordlists/endpoints.txt --threads 20
```

---

## ⚙️ Options

| Flag | Deskripsi | Default |
|------|-----------|---------|
| `-d, --domain` | Target domain (**wajib**) | — |
| `-k, --token` | GitHub API token | — |
| `--crawl` | Enable real-time web spider | `false` |
| `--active` | Enable wordlist-based scan | `false` |
| `--sources` | Comma-separated: `github,gitlab,bitbucket` | dari config |
| `--timing` | Stealth timing: `fast`/`normal`/`slow`/`random` | `normal` |
| `--max-pages` | Max halaman crawl | `100` |
| `--max-depth` | Max kedalaman spider | `4` |
| `--seed` | Custom seed URL | homepage target |
| `--follow-subs` | Ikut crawl subdomain | `false` |
| `--no-js` | Skip parse JS external | `false` |
| `--no-validate` | Skip HTTP validation | `false` |
| `--wordlist` | Path wordlist (active mode) | `wordlists/endpoints.txt` |
| `--threads` | Thread count (active mode) | `10` |
| `--deep` | Deep crawl repo tree (OSINT) | `false` |
| `--debug` | Enable debug output | `false` |

### Stealth Timing Modes

| Mode | Delay | Use Case |
|------|-------|----------|
| `fast` | 0.3–1.5s | Aggressive, lebih mudah terdeteksi |
| `normal` | 1.0–4.0s | **Recommended** untuk CTF/bug bounty |
| `slow` | 3.0–8.0s | Maximum stealth, target sensitif/production |
| `random` | mix acak | Distribusi paling natural |

---

## 📊 Output

Hasil scan tersimpan otomatis di `results/`:

```
results/
├── endpoints.txt         # Endpoint per kategori
├── parameters.txt        # Parameter yang ditemukan
└── scan_results.json     # Full data + metadata
```

### 4-Way Endpoint Classification

| Kategori | Arti | Prioritas |
|----------|------|-----------|
| ⚠️ **PRIVATE-OPEN** | Endpoint sensitif **TERBUKA** (200) | 🔥 **Tinggi** |
| ✅ **PUBLIC-OPEN** | Endpoint umum, accessible | Normal |
| 🔒 **PRIVATE-CLOSED** | Endpoint sensitif terkunci (401/403) | Medium |
| ⚪ **PUBLIC-CLOSED** | Endpoint umum tidak accessible (404) | Rendah |

---

## 🏗️ Project Structure

```
ShadowPath/
├── main.py                     # Entry point CLI
├── config.py                   # Konfigurasi global
├── core/                       # Core engine
│   ├── stealth.py              # UA rotation, timing jitter
│   ├── web_crawler.py          # Real-time HTML/JS spider
│   ├── live_checker.py         # DNS + HTTP liveness
│   ├── classifier.py           # 4-way classification
│   ├── github_search.py        # Multi-source OSINT
│   └── ...
├── scanner/                    # Scan pipelines
│   ├── crawl_scanner.py        # Crawl mode orchestrator
│   ├── endpoint_scanner.py     # OSINT pipeline
│   └── active_scanner.py       # Wordlist scan
├── filters/                    # Filter & scoring
├── utils/                      # Logger, output, helpers
├── wordlists/                  # Wordlists untuk active mode
└── results/                    # Output (gitignored)
```

---

## ⚖️ Legal & Ethics

> ⚠️ **Gunakan hanya pada target yang kamu punya izin eksplisit.**

Kategori penggunaan yang **legal**:
- ✅ Lab / VM sendiri
- ✅ CTF platform (HackTheBox, TryHackMe, PortSwigger Web Security Academy, dll)
- ✅ Bug bounty program (**harus in-scope**, cek scope program)
- ✅ Pentest engagement dengan authorization tertulis dari klien

Penggunaan tanpa izin melanggar hukum di banyak negara — di Indonesia melanggar **UU ITE Pasal 30**. Author tidak bertanggung jawab atas penyalahgunaan.

---

## 🤝 Contributing

Pull request, issue report, dan feature suggestion welcome. Untuk perubahan besar, buka issue dulu supaya bisa didiskusikan.

---

## 📄 License

MIT © [Author]
