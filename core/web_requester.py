import requests
import urllib3
import random
import time
import hashlib
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WebRequester:
    def __init__(self, timeout=10, delay_range=(1, 3)):
        self.timeout = timeout
        self.delay_range = delay_range
        self.session = requests.Session()

        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        ]

        # Statistik request
        self._stats = {
            "total": 0,
            "success": 0,
            "failed": 0,
            "by_status": {},
        }

    # =========================
    # 🔹 HEADERS
    # =========================
    def _headers(self, extra: dict = None) -> dict:
        h = {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        if extra:
            h.update(extra)
        return h

    def _delay(self):
        time.sleep(random.uniform(*self.delay_range))

    # =========================
    # 🌐 SINGLE REQUEST
    # =========================
    def request(self, url: str, method: str = "GET",
                extra_headers: dict = None, data: dict = None) -> dict | None:
        """
        Kirim request ke URL.

        Returns dict:
          url, status_code, content_length, fingerprint,
          content (5000 char), redirect_url, server, content_type
        """
        try:
            self._delay()
            self._stats["total"] += 1

            kwargs = {
                "headers": self._headers(extra_headers),
                "timeout": self.timeout,
                "allow_redirects": True,
                "verify": False,
            }
            if data and method.upper() in ("POST", "PUT", "PATCH"):
                kwargs["data"] = data

            response = self.session.request(method.upper(), url, **kwargs)

            content = response.text
            fp = hashlib.md5(" ".join(content.split()).encode()).hexdigest()
            redirect_url = response.url if response.url != url else None

            status = response.status_code
            self._stats["success"] += 1
            self._stats["by_status"][status] = self._stats["by_status"].get(status, 0) + 1

            return {
                "url": url,
                "status_code": status,
                "content_length": len(content),
                "fingerprint": fp,
                "content": content[:5000],
                "redirect_url": redirect_url,
                "server": response.headers.get("Server", ""),
                "content_type": response.headers.get("Content-Type", ""),
                "response_time": response.elapsed.total_seconds(),
            }

        except requests.exceptions.Timeout:
            self._stats["failed"] += 1
            return {"url": url, "status_code": None, "error": "timeout"}
        except requests.exceptions.ConnectionError:
            self._stats["failed"] += 1
            return {"url": url, "status_code": None, "error": "connection_error"}
        except requests.exceptions.RequestException as e:
            self._stats["failed"] += 1
            return {"url": url, "status_code": None, "error": str(e)}
        except Exception as e:
            self._stats["failed"] += 1
            return {"url": url, "status_code": None, "error": f"unexpected: {e}"}

    # =========================
    # 🔁 BATCH REQUEST
    # =========================
    def request_multiple(self, urls: list, method: str = "GET",
                          extra_headers: dict = None) -> list:
        """
        Request banyak URL sekaligus dengan progress tracking.
        Returns: list of result dict (termasuk yang error, untuk analisis)
        """
        results = []
        total = len(urls)

        for i, url in enumerate(urls, 1):
            print(f"[WebRequester] ({i}/{total}) {method} {url}")
            result = self.request(url, method=method, extra_headers=extra_headers)
            if result:
                results.append(result)

        return results

    # =========================
    # 🔍 FILTER HASIL
    # =========================
    def filter_by_status(self, results: list, status_codes: list) -> list:
        """Filter hasil berdasarkan status code."""
        return [r for r in results if r.get("status_code") in status_codes]

    def filter_successful(self, results: list) -> list:
        """Return hanya hasil dengan status 2xx."""
        return [r for r in results if r.get("status_code") and 200 <= r["status_code"] < 300]

    def filter_interesting(self, results: list) -> list:
        """Return hasil yang menarik: 200, 301, 302, 401, 403, 405, 500."""
        interesting = {200, 201, 301, 302, 307, 401, 403, 405, 429, 500, 503}
        return [r for r in results if r.get("status_code") in interesting]

    # =========================
    # 📊 STATISTIK
    # =========================
    def get_stats(self) -> dict:
        return self._stats.copy()

    def print_stats(self):
        s = self._stats
        print("\n" + "=" * 45)
        print("  📊 REQUEST STATISTICS")
        print("=" * 45)
        print(f"  Total     : {s['total']}")
        print(f"  ✅ Sukses  : {s['success']}")
        print(f"  ❌ Gagal   : {s['failed']}")
        print("  Status breakdown:")
        for code, count in sorted(s["by_status"].items()):
            print(f"    [{code}] {count}x")
        print("=" * 45 + "\n")

    # =========================
    # 🔄 RESET SESSION
    # =========================
    def reset_session(self):
        """Buat session baru (clear cookies, dll)."""
        self.session.close()
        self.session = requests.Session()
