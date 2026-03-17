# ShadowPath

Hidden Endpoint Discovery Engine

ShadowPath adalah tools untuk menemukan endpoint tersembunyi dari source code publik di GitHub berdasarkan target domain.

---

## 🚀 Features

- GitHub source code search
- Endpoint extraction (URL & path)
- Parameter extraction
- Endpoint classification (public / hidden)
- Domain filtering (target-specific)
- Optional endpoint validation (real-time)
- Clean CLI output
- JSON output support

---

## ⚙️ Installation

```bash
git clone https://github.com/username/ShadowPath
cd ShadowPath
pip install -r requirements.txt

## Run

python3 main.py -d target.com

## Options

-d   Target domain
-k   GitHub token (optional)

## Output

- Public endpoints
- Hidden endpoints
- Parameters

## Notes

- Uses GitHub as source intelligence
- Not brute-force scanner
- Use only on authorized targets
