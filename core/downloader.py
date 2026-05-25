import requests
import time
import random
from urllib.parse import urlparse


class Downloader:
    def __init__(self, timeout=10, delay_range=(1, 3)):
        self.timeout = timeout
        self.delay_range = delay_range
        self.session = requests.Session()
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        ]

    def _headers(self):
        return {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }

    def _polite_delay(self):
        """Delay sopan agar tidak membebani server."""
        time.sleep(random.uniform(*self.delay_range))

    # =========================
    # 🔹 SINGLE FETCH
    # =========================
    def fetch(self, url: str) -> str | None:
        try:
            self._polite_delay()
            r = self.session.get(
                url,
                headers=self._headers(),
                timeout=self.timeout,
                allow_redirects=True,
            )
            if r.status_code == 200:
                return r.text
            return None
        except requests.RequestException:
            return None

    # =========================
    # 🔹 BATCH FETCH
    # =========================
    def fetch_multiple(self, items: list) -> dict:
        """
        Fetch multiple raw URLs.
        items: list of dict dengan key 'raw_url'
        Returns: dict {raw_url: content}
        """
        results = {}
        for item in items:
            raw_url = item.get("raw_url")
            if not raw_url:
                continue
            content = self.fetch(raw_url)
            if content:
                results[raw_url] = content
        return results

    # =========================
    # 🌐 MULTI-SOURCE FETCH
    # =========================
    def detect_source(self, url: str) -> str:
        """Deteksi sumber dari URL."""
        host = urlparse(url).netloc.lower()
        if "github" in host:
            return "github"
        if "gitlab" in host:
            return "gitlab"
        if "bitbucket" in host:
            return "bitbucket"
        return "generic"

    def normalize_raw_url(self, url: str, source: str = None) -> str:
        """
        Normalisasi URL ke raw content URL sesuai platform.
        """
        src = source or self.detect_source(url)

        if src == "github":
            return (
                url.replace("github.com", "raw.githubusercontent.com")
                   .replace("/blob/", "/")
            )

        if src == "gitlab":
            # https://gitlab.com/user/repo/-/blob/main/file.py
            # -> https://gitlab.com/user/repo/-/raw/main/file.py
            return url.replace("/-/blob/", "/-/raw/")

        if src == "bitbucket":
            # https://bitbucket.org/user/repo/src/main/file.py
            # -> https://bitbucket.org/user/repo/raw/main/file.py
            return url.replace("/src/", "/raw/")

        return url

    def fetch_from_source(self, url: str) -> str | None:
        """Fetch dengan auto-normalisasi URL berdasarkan platform."""
        raw_url = self.normalize_raw_url(url)
        return self.fetch(raw_url)
