"""
core/web_crawler.py — Real-Time Web Crawler
=============================================
Spider langsung ke target web, extract endpoint dari:
  - HTML (href, action, src, data-url, meta refresh)
  - Inline JavaScript (fetch, axios, XHR, route definitions)
  - External JS files yang di-load oleh halaman
  - HTML forms (action + method)
  - Sitemap.xml / robots.txt

Flow:
  1. Mulai dari seed URL (homepage atau URL yang ditentukan)
  2. Download halaman dengan StealthSession
  3. Extract semua link dan JS endpoint dari konten
  4. Filter: hanya URL dalam domain target (DomainFilter)
  5. Tambah URL baru ke queue
  6. Repeat sampai queue habis atau batas page tercapai

Berbeda dengan active_scanner (wordlist-based), crawler ini
menemukan path yang benar-benar ada di aplikasi target.
"""

import re
from collections import deque
from urllib.parse import urlparse, urljoin, urlunparse
from html.parser import HTMLParser

from core.stealth import StealthSession
from core.endpoint_extractor import EndpointExtractor
from filters.domain_filter import DomainFilter
from utils.logger import Logger


# =============================================================
# 🔍 HTML LINK EXTRACTOR
# =============================================================
class _LinkParser(HTMLParser):
    """Extract semua link dari HTML tanpa dependency lxml/bs4."""

    _LINK_ATTRS = {
        "a":       ["href"],
        "form":    ["action"],
        "iframe":  ["src"],
        "frame":   ["src"],
        "script":  ["src"],
        "link":    ["href"],
        "img":     ["src", "data-src"],
        "source":  ["src"],
        "meta":    ["content"],  # meta refresh
        "button":  ["formaction", "data-url", "data-href"],
        "div":     ["data-url", "data-href", "data-src"],
        "span":    ["data-url", "data-href"],
        "input":   ["formaction"],
        "area":    ["href"],
    }

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url  = base_url
        self.links: list[str] = []
        self.scripts: list[str] = []   # URL script external
        self.forms: list[dict] = []    # {action, method}
        self._in_script = False
        self._script_content = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)

        # Script tag — bisa external atau inline
        if tag == "script":
            self._in_script = True
            src = attrs_dict.get("src", "")
            if src:
                full = self._resolve(src)
                if full:
                    self.scripts.append(full)
            return

        # Form
        if tag == "form":
            action = attrs_dict.get("action", "")
            method = attrs_dict.get("method", "GET").upper()
            if action:
                full = self._resolve(action)
                if full:
                    self.forms.append({"action": full, "method": method})
                    self.links.append(full)
            return

        # Generic link attrs
        for attr_name in self._LINK_ATTRS.get(tag, []):
            val = attrs_dict.get(attr_name, "")
            if not val or val.startswith("#") or val.startswith("javascript:"):
                continue
            # meta refresh: content="5; url=..."
            if tag == "meta" and attr_name == "content":
                m = re.search(r'url=([^\s;]+)', val, re.IGNORECASE)
                val = m.group(1) if m else ""
            if val:
                full = self._resolve(val)
                if full:
                    self.links.append(full)

        # data-* attrs lainnya — scan semua attr
        for attr_name, attr_val in attrs_dict.items():
            if attr_name.startswith("data-") and attr_val:
                if attr_val.startswith("/") or attr_val.startswith("http"):
                    full = self._resolve(attr_val)
                    if full:
                        self.links.append(full)

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script:
            self._script_content.append(data)

    def get_inline_script(self) -> str:
        return "\n".join(self._script_content)

    def _resolve(self, url: str) -> str | None:
        url = url.strip()
        if not url or url.startswith("data:") or url.startswith("blob:"):
            return None
        try:
            return urljoin(self.base_url, url)
        except Exception:
            return None


# =============================================================
# 🕸️ WEB CRAWLER
# =============================================================
class WebCrawler:
    """
    Real-time crawler yang spider dari seed URL secara rekursif.
    """

    # File extension yang tidak perlu di-crawl (resource statis)
    _SKIP_EXT = {
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg", ".ico",
        ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".mp4", ".mp3", ".avi", ".mov", ".webm", ".ogg", ".wav",
        ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
        ".exe", ".dmg", ".pkg", ".deb",
    }

    def __init__(self,
                 target_domain: str,
                 max_pages: int = 100,
                 max_depth: int = 4,
                 timing_mode: str = "normal",
                 crawl_js: bool = True,
                 follow_subdomains: bool = False,
                 timeout: int = 15,
                 known_scheme: str = ""):
        """
        Args:
            target_domain: domain target, misal 'example.com'
            max_pages: maksimum halaman yang di-crawl (default 100)
            max_depth: kedalaman maksimum crawl dari seed
            timing_mode: "fast"|"normal"|"slow"|"random"
            crawl_js: ikut download dan parse file JS external
            follow_subdomains: ikut crawl subdomain target
            timeout: HTTP timeout per request
            known_scheme: scheme yang sudah diketahui (http/https) dari liveness
                          check sebelumnya — kalau diisi, skip probe HTTPS/HTTP
        """
        self.target       = target_domain.lower().strip()
        self.max_pages    = max_pages
        self.max_depth    = max_depth
        self.crawl_js     = crawl_js
        self.timeout      = timeout
        self._known_scheme = known_scheme  # dari LiveChecker, skip probe kalau ada

        self.session      = StealthSession(
            timing_mode=timing_mode,
            timeout=timeout,
            interleave=True,
        )
        self.domain_filter = DomainFilter(
            target_domain,
            include_subdomains=follow_subdomains,
        )
        self.ep_extractor  = EndpointExtractor()

        # State
        self._visited:    set[str] = set()
        self._js_visited: set[str] = set()
        self._queue: deque = deque()  # (url, depth) — gunakan len() bukan qsize()
        self._pages_crawled = 0
        self._scheme = "https"  # resolved saat crawl() dipanggil (HTTPS/HTTP fallback)

        # Output
        self.found_urls:     set[str]  = set()   # semua URL yang ditemukan
        self.found_endpoints: set[str] = set()   # endpoint dari JS/HTML content
        self.found_forms:    list[dict] = []
        self.found_scripts:  set[str]  = set()

        # Raw responses untuk scan lanjutan
        self.raw_pages: dict[str, str] = {}  # url → content

    # =============================================================
    # 🚀 MAIN CRAWL
    # =============================================================
    def crawl(self, seed_url: str = None) -> dict:
        """
        Mulai crawling dari seed_url (default: https://<target>/).

        Returns dict:
          urls, endpoints, forms, scripts, raw_pages, stats
        """
        if not seed_url:
            # Kalau scheme sudah diketahui dari liveness check sebelumnya, pakai itu
            # langsung — hindari probe HTTPS/HTTP ulang (hemat 1 request + hindari
            # "1 failed" palsu di stats saat target hanya serve HTTP).
            if self._known_scheme:
                self._scheme = self._known_scheme
            else:
                # Auto-resolve scheme: test HTTPS dulu, fallback ke HTTP kalau gagal.
                # Banyak target lama (termasuk test target) cuma serve di HTTP port 80,
                # kalau langsung pakai HTTPS bakal timeout dan crawl 0 hasil.
                self._scheme = self._resolve_scheme()
            seed_url = f"{self._scheme}://{self.target}/"
        else:
            # Ambil scheme dari seed yang diberikan user
            from urllib.parse import urlparse as _up
            self._scheme = _up(seed_url).scheme or "https"

        # Normalize seed
        seed_url = self._normalize_url(seed_url)
        Logger.info(f"Starting crawl: {seed_url}")
        Logger.info(f"Max pages: {self.max_pages}, Max depth: {self.max_depth}")

        # Tambah robots.txt dan sitemap sebagai seed tambahan (pakai scheme yang resolved)
        base = f"{self._scheme}://{self.target}"
        for extra in ["/robots.txt", "/sitemap.xml", "/sitemap_index.xml"]:
            self._queue.append((base + extra, 0))

        # Seed utama
        self._queue.appendleft((seed_url, 0))

        while self._queue and self._pages_crawled < self.max_pages:
            url, depth = self._queue.popleft()

            if url in self._visited:
                continue
            if depth > self.max_depth:
                continue
            if self._should_skip(url):
                continue

            self._visited.add(url)
            self._crawl_page(url, depth)

        Logger.success(
            f"Crawl complete — pages: {self._pages_crawled}, "
            f"URLs found: {len(self.found_urls)}, "
            f"Endpoints: {len(self.found_endpoints)}"
        )

        return self._build_result()

    # =============================================================
    # 📄 CRAWL SINGLE PAGE
    # =============================================================
    def _resolve_scheme(self) -> str:
        """
        Tentukan scheme yang benar untuk target: HTTPS dulu, fallback HTTP.

        Banyak target (terutama aplikasi lama / test target) hanya serve di
        HTTP port 80. Kalau crawler langsung ngotot HTTPS, semua request
        timeout dan hasil crawl 0. Method ini test HTTPS sekali; kalau gagal,
        pakai HTTP.
        """
        https_url = f"https://{self.target}/"
        result = self.session.get(https_url, skip_delay=True)
        if result and result.get("status_code"):
            return "https"

        http_url = f"http://{self.target}/"
        result = self.session.get(http_url, skip_delay=True)
        if result and result.get("status_code"):
            Logger.warn(f"HTTPS gagal, menggunakan HTTP untuk {self.target}")
            return "http"

        # Dua-duanya gagal — default ke https (nanti error di-handle downstream)
        Logger.warn(f"HTTPS & HTTP dua-duanya gagal untuk {self.target}")
        return "https"

    def _crawl_page(self, url: str, depth: int):
        self._pages_crawled += 1
        Logger.info(f"[{self._pages_crawled}/{self.max_pages}] Crawling (d={depth}): {url}")

        result = self.session.get(url)
        if not result or not result.get("status_code"):
            return

        status  = result["status_code"]
        content = result.get("content", "")
        ctype   = result.get("content_type", "")

        # Simpan konten untuk scan lanjutan
        if content and status in (200, 401, 403):
            self.raw_pages[url] = content

        # Hanya parse HTML/JS
        if "javascript" in ctype or url.endswith(".js"):
            self._process_js(url, content)
            return

        if "html" not in ctype and not url.endswith((".html", ".htm", "/", "")):
            return

        if not content:
            return

        # robots.txt — extract disallowed paths
        if url.endswith("robots.txt"):
            self._parse_robots(content, url)
            return

        # sitemap.xml
        if "sitemap" in url or "xml" in ctype:
            self._parse_sitemap(content, url)
            return

        # Parse HTML
        self._process_html(url, content, depth)

    # =============================================================
    # 🌐 PROCESS HTML
    # =============================================================
    def _process_html(self, url: str, content: str, depth: int):
        parser = _LinkParser(base_url=url)
        try:
            parser.feed(content)
        except Exception:
            pass

        # Tambah semua link ke queue
        for link in parser.links:
            norm = self._normalize_url(link)
            if norm and norm not in self._visited:
                if self.domain_filter.is_valid(norm):
                    self.found_urls.add(norm)
                    self._queue.append((norm, depth + 1))

        # Script external
        for script_url in parser.scripts:
            norm = self._normalize_url(script_url)
            if norm:
                self.found_scripts.add(norm)
                if self.crawl_js and norm not in self._js_visited:
                    self._queue.append((norm, depth + 1))

        # Forms
        self.found_forms.extend(parser.forms)

        # Extract endpoint dari inline JS
        inline_js = parser.get_inline_script()
        if inline_js:
            eps = self.ep_extractor.extract_from_text(inline_js)
            for ep in eps:
                full = self._to_full_url(ep, url)
                if full:
                    self.found_endpoints.add(full)

        # Extract endpoint dari seluruh HTML content juga
        eps_html = self.ep_extractor.extract_from_text(content)
        for ep in eps_html:
            full = self._to_full_url(ep, url)
            if full:
                self.found_endpoints.add(full)

    # =============================================================
    # ⚙️ PROCESS JS
    # =============================================================
    def _process_js(self, url: str, content: str):
        """Extract endpoint dari file JS."""
        if not content:
            return
        self._js_visited.add(url)
        eps = self.ep_extractor.extract_from_text(content)
        for ep in eps:
            full = self._to_full_url(ep, url)
            if full:
                self.found_endpoints.add(full)
                self.found_urls.add(full)

    # =============================================================
    # 🤖 PARSE ROBOTS.TXT
    # =============================================================
    def _parse_robots(self, content: str, base_url: str):
        """Extract path dari robots.txt (Allow + Disallow)."""
        base = f"{self._scheme}://{self.target}"
        for line in content.splitlines():
            line = line.strip()
            if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                parts = line.split(":", 1)
                if len(parts) != 2:
                    continue
                directive, value = parts[0].lower(), parts[1].strip()

                if directive == "sitemap":
                    norm = self._normalize_url(value)
                    if norm:
                        self._queue.append((norm, 0))
                elif value and value != "/":
                    # Wildcard patterns — ambil prefix
                    path = value.split("*")[0].split("$")[0].strip()
                    if path and path.startswith("/"):
                        full_url = base + path
                        self.found_urls.add(full_url)
                        self.found_endpoints.add(full_url)
                        if directive == "disallow":
                            Logger.info(f"  [robots] Disallowed path found: {full_url}")

    # =============================================================
    # 🗺️ PARSE SITEMAP.XML
    # =============================================================
    def _parse_sitemap(self, content: str, base_url: str):
        """Extract URL dari sitemap XML."""
        # <loc>URL</loc> pattern
        locs = re.findall(r'<loc>\s*(https?://[^\s<]+)\s*</loc>', content)
        for loc in locs:
            norm = self._normalize_url(loc)
            if norm and norm not in self._visited:
                # Sitemap bisa referensikan sub-sitemap
                if "sitemap" in norm.lower() and norm.endswith(".xml"):
                    self._queue.append((norm, 0))
                elif self.domain_filter.is_valid(norm):
                    self.found_urls.add(norm)
                    self._queue.append((norm, 1))

    # =============================================================
    # 🔧 HELPERS
    # =============================================================
    def _normalize_url(self, url: str) -> str | None:
        """Normalisasi URL: lowercase scheme+host, strip fragment, strip trailing ?."""
        if not url:
            return None
        url = url.strip()
        try:
            p = urlparse(url)
            if p.scheme not in ("http", "https"):
                return None
            # Lowercase host
            normalized = urlunparse((
                p.scheme.lower(),
                p.netloc.lower(),
                p.path,
                p.params,
                p.query,
                "",  # strip fragment
            ))
            # Strip trailing ?
            if normalized.endswith("?"):
                normalized = normalized[:-1]
            return normalized
        except Exception:
            return None

    def _to_full_url(self, ep: str, base_url: str) -> str | None:
        """Convert relative path ke full URL dan validasi domain."""
        if not ep:
            return None
        try:
            if ep.startswith("http"):
                parsed = urlparse(ep)
                if self.domain_filter.is_valid(ep):
                    return self._normalize_url(ep)
                return None
            elif ep.startswith("/"):
                parsed_base = urlparse(base_url)
                full = f"{parsed_base.scheme}://{parsed_base.netloc}{ep}"
                return self._normalize_url(full)
        except Exception:
            pass
        return None

    def _should_skip(self, url: str) -> bool:
        """Return True jika URL tidak perlu di-crawl."""
        if not url:
            return True
        try:
            p = urlparse(url)
            path = p.path.lower()

            # Skip resource statis
            for ext in self._SKIP_EXT:
                if path.endswith(ext):
                    return True

            # Skip fragment-only
            if not p.netloc:
                return True

            return False
        except Exception:
            return True

    def _build_result(self) -> dict:
        return {
            "urls":       list(self.found_urls),
            "endpoints":  list(self.found_endpoints),
            "forms":      self.found_forms,
            "scripts":    list(self.found_scripts),
            "raw_pages":  self.raw_pages,
            "stats": {
                "pages_crawled": self._pages_crawled,
                "urls_found":    len(self.found_urls),
                "endpoints":     len(self.found_endpoints),
                "forms":         len(self.found_forms),
                "js_files":      len(self.found_scripts),
            },
        }

    def close(self):
        self.session.close()
