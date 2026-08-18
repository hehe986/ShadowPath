"""
core/stealth.py — Stealth & Evasion Layer
==========================================
Tujuan: buat traffic ShadowPath semirip mungkin dengan browser biasa sehingga
tidak mudah terdeteksi oleh WAF, IDS, atau rate limiter sederhana.

Teknik yang diimplementasikan:
  1. User-Agent rotation (Chrome, Firefox, Safari, Edge — desktop & mobile)
  2. Realistic browser headers (Accept, Accept-Language, Accept-Encoding, dll)
  3. Referer spoofing — seolah datang dari Google/Bing search
  4. Timing jitter — delay non-uniform agar tidak terlihat sebagai bot
  5. Request interleaving — sesekali request ke resource statis (favicon, robots.txt)
     di sela request utama agar traffic pattern mirip real browsing
  6. Cookie jar persistence — session cookie disimpan antar request
  7. TLS/cipher order mimicry via requests (sejauh yang bisa dikontrol di Python)

CATATAN ETIS:
  Gunakan hanya pada target yang kamu punya izin eksplisit:
  lab lokal, CTF, bug bounty in-scope, atau pentest engagement.
"""

import random
import time
import requests
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =============================================================
# 🎭 USER-AGENT POOL
# =============================================================
# Diambil dari real browser fingerprint (Januari 2025).
# Mix desktop + mobile agar tidak monoton.
UA_POOL = {
    "chrome_win": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    ],
    "chrome_mac": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ],
    "firefox_win": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    ],
    "firefox_linux": [
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ],
    "safari_mac": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    ],
    "edge_win": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    ],
    "chrome_android": [
        "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    ],
    "safari_ios": [
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    ],
}

# Flat list dengan bobot — desktop lebih dominan (realistis)
_UA_WEIGHTED: list[str] = []
_UA_WEIGHTS = {
    "chrome_win":     30,
    "chrome_mac":     20,
    "firefox_win":    15,
    "firefox_linux":  10,
    "safari_mac":     10,
    "edge_win":        5,
    "chrome_android":  7,
    "safari_ios":      3,
}
for _k, _w in _UA_WEIGHTS.items():
    _UA_WEIGHTED.extend(UA_POOL[_k] * _w)


def random_ua() -> str:
    """Return UA acak dengan distribusi bobot realistis."""
    return random.choice(_UA_WEIGHTED)


def ua_browser_type(ua: str) -> str:
    """Deteksi tipe browser dari UA string."""
    ua_l = ua.lower()
    if "edg/" in ua_l:
        return "edge"
    if "firefox" in ua_l:
        return "firefox"
    if "safari" in ua_l and "chrome" not in ua_l:
        return "safari"
    return "chrome"


# =============================================================
# 📋 HEADER BUILDER
# =============================================================
# Accept header berbeda per browser agar lebih authentic.
_ACCEPT_BY_BROWSER = {
    "chrome":  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "firefox": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "safari":  "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "edge":    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
}

_ACCEPT_LANG_POOL = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.9,id;q=0.8",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.8",
    "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
]

_REFERER_POOL = [
    "https://www.google.com/",
    "https://www.google.com/search?q=site:{domain}",
    "https://www.bing.com/search?q={domain}",
    "https://duckduckgo.com/?q={domain}",
    "https://{domain}/",
    None,   # no referer (direct visit)
    None,   # weight up direct
]


def build_headers(ua: str = None, referer_domain: str = None,
                  extra: dict = None) -> dict:
    """
    Build realistic browser headers.

    Args:
        ua: user agent string; random jika None
        referer_domain: domain target untuk referer spoofing
        extra: header tambahan yang override defaults
    """
    ua = ua or random_ua()
    browser = ua_browser_type(ua)

    # Pilih Accept sesuai browser
    accept = _ACCEPT_BY_BROWSER.get(browser, _ACCEPT_BY_BROWSER["chrome"])

    # Referer — kadang ada, kadang tidak (seperti browsing nyata)
    referer_template = random.choice(_REFERER_POOL)
    if referer_template and referer_domain:
        referer = referer_template.format(domain=referer_domain)
    elif referer_template and "{domain}" not in referer_template:
        referer = referer_template
    else:
        referer = None

    headers = {
        "User-Agent":                ua,
        "Accept":                    accept,
        "Accept-Language":           random.choice(_ACCEPT_LANG_POOL),
        "Accept-Encoding":           "gzip, deflate, br",
        "Connection":                "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest":            "document",
        "Sec-Fetch-Mode":            "navigate",
        "Sec-Fetch-Site":            "none" if not referer else "cross-site",
        "Sec-Fetch-User":            "?1",
        "Cache-Control":             random.choice(["max-age=0", "no-cache", ""]),
    }

    # DNT (Do Not Track) — kadang ada
    if random.random() < 0.3:
        headers["DNT"] = "1"

    if referer:
        headers["Referer"] = referer

    # Hapus key kosong
    headers = {k: v for k, v in headers.items() if v}

    if extra:
        headers.update(extra)

    return headers


# =============================================================
# ⏱️ TIMING ENGINE
# =============================================================
class TimingEngine:
    """
    Generate delay realistis yang meniru pola browsing manusia.

    Manusia tidak request dengan interval seragam — ada baca halaman,
    klik link, loading resource, dll. Engine ini mensimulasikan pola itu.
    """

    def __init__(self, mode: str = "normal"):
        """
        mode:
          "fast"    — 0.3–1.5s  (aggressive, lebih mudah terdeteksi)
          "normal"  — 1.0–4.0s  (default, balance antara kecepatan & stealth)
          "slow"    — 3.0–8.0s  (sangat mirip manusia, cocok untuk target sensitif)
          "random"  — mix semua mode secara acak
        """
        self.mode = mode
        self._request_count = 0
        self._last_request_time = 0.0

        self._ranges = {
            "fast":   (0.3, 1.5),
            "normal": (1.0, 4.0),
            "slow":   (3.0, 8.0),
        }

    def wait(self):
        """Tunggu sebelum request berikutnya dengan delay yang realistis."""
        self._request_count += 1

        if self.mode == "random":
            mode = random.choice(["fast", "normal", "normal", "slow"])
        else:
            mode = self.mode

        lo, hi = self._ranges[mode]

        # Gaussian jitter — lebih natural dari uniform
        mean  = (lo + hi) / 2
        sigma = (hi - lo) / 4
        delay = max(lo, min(hi, random.gauss(mean, sigma)))

        # Sesekali tambah "reading pause" — seperti user baca halaman dulu
        if self._request_count % random.randint(5, 12) == 0:
            delay += random.uniform(2.0, 6.0)

        time.sleep(delay)

    def burst_wait(self):
        """Delay pendek untuk request resource sekunder (CSS, favicon, dll)."""
        time.sleep(random.uniform(0.05, 0.3))


# =============================================================
# 🕵️ STEALTH SESSION
# =============================================================
class StealthSession:
    """
    requests.Session dengan stealth layer terintegrasi.

    Fitur:
    - UA konsisten per session (tidak ganti tiap request)
    - Cookie persistence otomatis
    - Header builder terintegrasi
    - TimingEngine built-in
    - Interleaving request statis (favicon, robots.txt) untuk noise realistis
    - Auto-retry dengan backoff pada rate limit (429)
    """

    def __init__(self,
                 timing_mode: str = "normal",
                 verify_ssl: bool = False,
                 timeout: int = 10,
                 rotate_ua: bool = True,
                 interleave: bool = True):
        """
        Args:
            timing_mode: "fast" | "normal" | "slow" | "random"
            verify_ssl: verifikasi SSL cert (False untuk pentest)
            timeout: request timeout dalam detik
            rotate_ua: ganti UA setiap N request
            interleave: sesekali request resource statis untuk noise
        """
        self.verify_ssl   = verify_ssl
        self.timeout      = timeout
        self.rotate_ua    = rotate_ua
        self.interleave   = interleave

        self._session     = requests.Session()
        self._timer       = TimingEngine(mode=timing_mode)
        self._ua          = random_ua()
        self._ua_counter  = 0
        self._ua_rotate_every = random.randint(8, 20)  # rotate setiap 8–20 req

        self._req_count   = 0
        self._domain_cache: dict[str, str] = {}  # domain → base URL

        # Stats
        self.stats = {
            "total": 0, "success": 0, "failed": 0,
            "rate_limited": 0, "by_status": {}
        }

    # ── Internal ──────────────────────────────────────────────
    def _current_ua(self) -> str:
        """Return UA saat ini; rotate jika sudah waktunya."""
        if self.rotate_ua:
            self._ua_counter += 1
            if self._ua_counter >= self._ua_rotate_every:
                self._ua = random_ua()
                self._ua_counter = 0
                self._ua_rotate_every = random.randint(8, 20)
        return self._ua

    def _get_domain(self, url: str) -> str:
        parsed = urlparse(url)
        return parsed.netloc or url

    def _static_noise(self, base_url: str):
        """
        Request resource statis yang tidak penting untuk menciptakan noise.
        Mirip browser yang otomatis load favicon, robots.txt, dll.
        Dilakukan tanpa delay besar dan error diabaikan.
        """
        noise_paths = ["/favicon.ico", "/robots.txt", "/sitemap.xml"]
        path = random.choice(noise_paths)
        url  = base_url.rstrip("/") + path
        try:
            self._timer.burst_wait()
            self._session.get(
                url,
                headers=build_headers(self._ua),
                timeout=5,
                verify=self.verify_ssl,
                allow_redirects=False,
            )
        except Exception:
            pass  # noise request — hasil tidak penting

    # ── Public API ────────────────────────────────────────────
    def get(self, url: str, extra_headers: dict = None,
            skip_delay: bool = False) -> dict | None:
        """
        GET request dengan stealth layer.

        Returns dict:
          url, status_code, content, content_length, content_type,
          fingerprint, redirect_url, server, response_time, headers
        """
        return self._request("GET", url, extra_headers=extra_headers,
                             skip_delay=skip_delay)

    def head(self, url: str) -> dict | None:
        """HEAD request — untuk cek keberadaan endpoint tanpa download body."""
        return self._request("HEAD", url, skip_delay=True)

    def _request(self, method: str, url: str,
                 extra_headers: dict = None,
                 data: dict = None,
                 skip_delay: bool = False) -> dict | None:
        if not skip_delay:
            self._timer.wait()

        self._req_count += 1
        self.stats["total"] += 1

        # Interleave noise sesekali
        if self.interleave and self._req_count % random.randint(7, 15) == 0:
            domain = self._get_domain(url)
            parsed = urlparse(url)
            base   = f"{parsed.scheme}://{parsed.netloc}"
            self._static_noise(base)

        ua      = self._current_ua()
        domain  = self._get_domain(url)
        headers = build_headers(ua=ua, referer_domain=domain,
                                extra=extra_headers)

        try:
            kwargs: dict = {
                "headers":         headers,
                "timeout":         self.timeout,
                "verify":          self.verify_ssl,
                "allow_redirects": True,
            }
            if data and method.upper() in ("POST", "PUT", "PATCH"):
                kwargs["data"] = data

            resp    = self._session.request(method.upper(), url, **kwargs)
            content = resp.text if method.upper() != "HEAD" else ""

            import hashlib
            fp = hashlib.md5(" ".join(content.split()).encode()).hexdigest() if content else ""

            status = resp.status_code
            self.stats["success"] += 1
            self.stats["by_status"][status] = self.stats["by_status"].get(status, 0) + 1

            # Rate limit — back off
            if status == 429:
                self.stats["rate_limited"] += 1
                retry_after = int(resp.headers.get("Retry-After", 30))
                from utils.logger import Logger
                Logger.warn(f"[Stealth] 429 Rate Limited — backing off {retry_after}s")
                time.sleep(retry_after + random.uniform(1, 5))

            return {
                "url":            url,
                "status_code":    status,
                "content":        content[:8000],
                "content_length": len(content),
                "content_type":   resp.headers.get("Content-Type", ""),
                "fingerprint":    fp,
                "redirect_url":   resp.url if resp.url != url else None,
                "server":         resp.headers.get("Server", ""),
                "response_time":  resp.elapsed.total_seconds(),
                "headers":        dict(resp.headers),
            }

        except requests.exceptions.Timeout as e:
            self.stats["failed"] += 1
            print(f"[DEBUG] Timeout: {url} - {e}")
            return {"url": url, "status_code": None, "error": "timeout", "content": ""}
        except requests.exceptions.ConnectionError as e:
            self.stats["failed"] += 1
            print(f"[DEBUG] ConnectionError: {url} - {e}")
            return {"url": url, "status_code": None, "error": "connection_error", "content": ""}
        except requests.exceptions.RequestException as e:
            self.stats["failed"] += 1
            print(f"[DEBUG] RequestException: {type(e).__name__} - {e}")
            return {"url": url, "status_code": None, "error": str(e), "content": ""}
        except Exception as e:
            self.stats["failed"] += 1
            print(f"[DEBUG] Unexpected: {type(e).__name__} - {e}")
            import traceback
            traceback.print_exc()
            return {"url": url, "status_code": None, "error": str(e), "content": ""}

    def close(self):
        self._session.close()

    def print_stats(self):
        from utils.logger import Logger
        s = self.stats
        Logger.section("STEALTH SESSION STATS")
        print(f"  Total requests   : {s['total']}")
        print(f"  ✅ Success       : {s['success']}")
        print(f"  ❌ Failed        : {s['failed']}")
        print(f"  ⚠️  Rate limited  : {s['rate_limited']}")
        print(f"  UA rotations     : {self._ua_counter // max(1, self._ua_rotate_every)}")
        print("  Status breakdown:")
        for code, count in sorted(s["by_status"].items()):
            print(f"    [{code}] {count}x")
