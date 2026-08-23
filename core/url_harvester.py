"""
core/url_harvester.py - Passive URL Harvester (gau-style)
==========================================================
Narik URL historis target dari sumber arsip publik, tanpa hit target
langsung. Mirip cara kerja 'gau' (getallurls).

Sumber:
  - Wayback Machine   (web.archive.org CDX API)
  - Common Crawl      (index.commoncrawl.org)
  - AlienVault OTX    (otx.alienvault.com passive URLs)
  - URLScan.io        (urlscan.io search API)

Semua sumber pasif — data diambil dari arsip pihak ketiga, bukan dari
crawl langsung ke target. Ini yang bikin bisa dapat ribuan URL termasuk
endpoint lama yang sudah tidak ter-link.
"""

import json
import re
from urllib.parse import urlparse

import requests

from utils.logger import Logger


class URLHarvester:
    """Kumpulkan URL dari arsip publik (passive)."""

    def __init__(self, target_domain: str,
                 include_subs: bool = True,
                 timeout: int = 20,
                 max_urls: int = 50000):
        self.target = self._clean_domain(target_domain)
        self.include_subs = include_subs
        self.timeout = timeout
        self.max_urls = max_urls

        self.found: set[str] = set()
        self.by_source: dict[str, int] = {
            "wayback": 0, "commoncrawl": 0, "otx": 0, "urlscan": 0,
        }

    def _clean_domain(self, d: str) -> str:
        d = d.strip().lower()
        if d.startswith(("http://", "https://")):
            d = urlparse(d).netloc or d
        return d.split("/")[0].split(":")[0]

    # =============================================================
    # MAIN
    # =============================================================
    def harvest(self) -> dict:
        Logger.section(f"URL HARVESTING (passive) - {self.target}")

        Logger.info("Sumber 1: Wayback Machine...")
        self._harvest_wayback()
        Logger.info("Sumber 2: Common Crawl...")
        self._harvest_commoncrawl()
        Logger.info("Sumber 3: AlienVault OTX...")
        self._harvest_otx()
        Logger.info("Sumber 4: URLScan.io...")
        self._harvest_urlscan()

        Logger.success(f"Total URL terkumpul: {len(self.found)}")
        for src, n in self.by_source.items():
            if n:
                print(f"    {src:<14}: {n}")

        return {
            "target": self.target,
            "urls": sorted(self.found),
            "total": len(self.found),
            "by_source": dict(self.by_source),
        }

    # =============================================================
    # SUMBER
    # =============================================================
    def _harvest_wayback(self):
        """Wayback Machine CDX API. Retry beberapa kali karena server sering lambat."""
        host = f"*.{self.target}/*" if self.include_subs else f"{self.target}/*"
        url = (f"https://web.archive.org/cdx/search/cdx"
               f"?url={host}&output=json&fl=original&collapse=urlkey"
               f"&limit={self.max_urls}")
        # Wayback sering lambat → timeout lebih panjang + retry
        wb_timeout = max(self.timeout, 60)
        max_retry = 3
        for attempt in range(1, max_retry + 1):
            try:
                r = requests.get(url, timeout=wb_timeout)
                if r.status_code != 200:
                    Logger.warn(f"Wayback returned {r.status_code}")
                    return
                data = r.json()
                for row in data[1:]:  # baris pertama header
                    if row and self._is_valid(row[0]):
                        self.found.add(row[0])
                        self.by_source["wayback"] += 1
                return  # sukses, keluar
            except requests.Timeout:
                if attempt < max_retry:
                    Logger.warn(f"Wayback timeout, retry {attempt}/{max_retry-1}...")
                    continue
                Logger.warn("Wayback timeout — dilewati (sumber lain tetap jalan)")
            except (requests.RequestException, json.JSONDecodeError, ValueError) as e:
                Logger.warn(f"Wayback error: {e}")
                return

    def _harvest_commoncrawl(self):
        """Common Crawl index (ambil index terbaru)."""
        try:
            # ambil daftar index CC terbaru
            r = requests.get("https://index.commoncrawl.org/collinfo.json",
                             timeout=self.timeout)
            if r.status_code != 200:
                return
            indexes = r.json()
            if not indexes:
                return
            # pakai index terbaru saja (yang paling atas)
            cdx_api = indexes[0].get("cdx-api")
            if not cdx_api:
                return
            host = f"*.{self.target}" if self.include_subs else self.target
            q = f"{cdx_api}?url={host}/*&output=json&limit={self.max_urls}"
            r2 = requests.get(q, timeout=self.timeout)
            if r2.status_code != 200:
                return
            for line in r2.text.splitlines():
                try:
                    obj = json.loads(line)
                    u = obj.get("url", "")
                    if self._is_valid(u):
                        self.found.add(u)
                        self.by_source["commoncrawl"] += 1
                except json.JSONDecodeError:
                    continue
        except (requests.RequestException, json.JSONDecodeError, ValueError) as e:
            Logger.warn(f"Common Crawl error: {e}")

    def _harvest_otx(self):
        """AlienVault OTX passive URLs."""
        page = 1
        while page <= 50:  # batasi 50 halaman
            api = (f"https://otx.alienvault.com/api/v1/indicators/"
                   f"domain/{self.target}/url_list?limit=500&page={page}")
            try:
                r = requests.get(api, timeout=self.timeout)
                if r.status_code != 200:
                    break
                data = r.json()
                url_list = data.get("url_list", [])
                if not url_list:
                    break
                for item in url_list:
                    u = item.get("url", "")
                    if self._is_valid(u):
                        self.found.add(u)
                        self.by_source["otx"] += 1
                if not data.get("has_next"):
                    break
                page += 1
            except (requests.RequestException, json.JSONDecodeError, ValueError) as e:
                Logger.warn(f"OTX error: {e}")
                break

    def _harvest_urlscan(self):
        """URLScan.io search."""
        api = f"https://urlscan.io/api/v1/search/?q=domain:{self.target}&size=10000"
        try:
            r = requests.get(api, timeout=self.timeout)
            if r.status_code != 200:
                return
            data = r.json()
            for result in data.get("results", []):
                u = result.get("page", {}).get("url", "")
                if self._is_valid(u):
                    self.found.add(u)
                    self.by_source["urlscan"] += 1
        except (requests.RequestException, json.JSONDecodeError, ValueError) as e:
            Logger.warn(f"URLScan error: {e}")

    # =============================================================
    # HELPER
    # =============================================================
    def _is_valid(self, url: str) -> bool:
        if not url or not url.startswith(("http://", "https://")):
            return False
        try:
            host = urlparse(url).netloc.lower().split(":")[0]
        except ValueError:
            return False
        if self.include_subs:
            return host == self.target or host.endswith("." + self.target)
        return host == self.target
