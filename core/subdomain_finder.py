"""
core/subdomain_finder.py - Full Subdomain Enumeration Engine
=============================================================
Kombinasi 3 teknik untuk temukan subdomain dari target domain:

  1. PASSIVE (aman, tidak hit target):
     - crt.sh              (Certificate Transparency logs)
     - AlienVault OTX      (threat intel database)
     - HackerTarget        (public DNS records)
     - Wayback Machine     (historical URLs)

  2. ACTIVE BRUTEFORCE:
     - DNS query dengan wordlist common subdomain
     - Concurrent resolver dengan thread pool

  3. PERMUTATION:
     - Kombinasi found subdomain dengan pattern common
       (api-v1, api-v2, dev-api, staging-api, dll)
     - Level-based (a.b.target.com -> permute a & b)

Semua hasil melewati LiveChecker untuk verifikasi hidup,
lalu di-return dengan status per subdomain.
"""

import re
import socket
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests

from core.stealth import StealthSession
from core.live_checker import LiveChecker, resolve_dns
from utils.logger import Logger


# =============================================================
# WORDLIST BUILT-IN
# =============================================================
# Common subdomain berdasarkan pentest reports & bug bounty writeups
# Kombinasi Top-1000 dari SecLists + custom Indonesian context
COMMON_SUBS = [
    # === TIER 1 - MOST COMMON ===
    "www", "mail", "ftp", "webmail", "admin", "test", "dev", "staging",
    "api", "blog", "shop", "app", "m", "mobile", "portal", "cdn",
    "static", "assets", "images", "img", "media", "video", "download",
    "docs", "wiki", "help", "support", "kb", "faq",

    # === AUTH & USER MANAGEMENT ===
    "login", "signin", "signup", "auth", "oauth", "sso", "account",
    "accounts", "user", "users", "member", "members", "profile",
    "dashboard", "panel", "cp", "cpanel", "webhosting",

    # === API & SERVICES ===
    "api1", "api2", "api-v1", "api-v2", "api-v3", "apiv1", "apiv2",
    "rest", "graphql", "grpc", "ws", "websocket", "service", "services",
    "microservice", "gateway", "proxy", "backend", "frontend",

    # === ENVIRONMENT ===
    "prod", "production", "stage", "staging", "qa", "uat", "sandbox",
    "beta", "alpha", "preview", "canary", "test1", "test2", "testing",
    "dev1", "dev2", "development", "local", "internal",

    # === INFRASTRUCTURE ===
    "vpn", "ssh", "sftp", "rdp", "remote", "monitor", "monitoring",
    "grafana", "prometheus", "kibana", "elastic", "elk", "jenkins",
    "gitlab", "git", "github", "svn", "ci", "cd", "cicd", "build",

    # === DATABASE ===
    "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
    "backup", "backups", "archive",

    # === MAIL & COMMUNICATION ===
    "smtp", "imap", "pop", "pop3", "mx", "mail2", "email", "newsletter",
    "chat", "chatbot", "irc", "jabber",

    # === CONTENT & MARKETING ===
    "news", "press", "media", "images", "img", "static", "css", "js",
    "blog", "forum", "community", "landing", "promo", "campaign",

    # === EDUCATION (context Indonesia) ===
    "elearning", "e-learning", "lms", "moodle", "siakad", "akademik",
    "mahasiswa", "dosen", "pmb", "spmb", "ppdb", "portal", "sim",
    "simak", "simpeg", "simak", "arsip", "perpustakaan", "library",
    "jurnal", "repository", "repo", "ojs", "ejournal",

    # === GOVERNMENT (context Indonesia) ===
    "layanan", "pelayanan", "aduan", "lapor", "eppid", "ppid",
    "dashboard", "monev", "e-office", "eoffice", "sikeu", "simkeu",

    # === COMMERCE ===
    "shop", "store", "cart", "checkout", "payment", "pay", "billing",
    "invoice", "order", "orders", "product", "products", "catalog",

    # === FILE & STORAGE ===
    "files", "storage", "s3", "cdn", "static", "media", "upload",
    "uploads", "downloads", "share", "sharing",

    # === HR & INTERNAL ===
    "hr", "hrd", "erp", "crm", "intranet", "internal", "office",
    "meeting", "conference", "hr-portal", "employee",

    # === DEBUG & ADMIN ===
    "admin", "administrator", "sysadmin", "root", "manage", "manager",
    "console", "debug", "trace", "log", "logs", "phpmyadmin", "pma",
    "adminer", "webmin", "plesk",

    # === CLOUD & CDN ===
    "cloudfront", "s3", "azure", "gcp", "aws", "heroku", "vercel",
    "netlify", "cloudflare",

    # === OLD/LEGACY ===
    "old", "new", "beta", "v1", "v2", "v3", "old-www", "old-api",
    "legacy", "backup", "temp", "tmp", "temporary",

    # === REGIONAL ===
    "id", "jakarta", "bandung", "surabaya", "en", "us", "asia",

    # === MISC HIGH VALUE ===
    "secret", "private", "hidden", "internal", "confidential",
    "vault", "keys", "tokens", "config", "configuration",
    "swagger", "docs", "documentation", "openapi", "redoc",
    "metrics", "health", "healthcheck", "status", "ping",
    ".well-known", "robots", "sitemap",
]

# Permutation patterns
_PERM_PREFIXES = ["dev", "staging", "test", "prod", "qa", "uat", "beta",
                  "old", "new", "internal", "external", "api", "admin"]
_PERM_SUFFIXES = ["dev", "staging", "test", "prod", "qa", "uat", "beta",
                  "old", "new", "v1", "v2", "v3", "2", "3"]


# =============================================================
# SUBDOMAIN FINDER
# =============================================================
class SubdomainFinder:
    """
    Full subdomain enumeration: passive + bruteforce + permutation.
    """

    def __init__(self,
                 target_domain: str,
                 max_subs: int = 500,
                 bruteforce: bool = True,
                 permutation: bool = True,
                 verify_liveness: bool = True,
                 timing_mode: str = "fast",
                 threads: int = 20,
                 timeout: int = 5):
        """
        Args:
            target_domain: root domain (e.g. "target.com")
            max_subs: batas maksimum subdomain yang di-enum (default 500)
            bruteforce: aktifkan DNS bruteforce
            permutation: aktifkan permutasi dari passive hits
            verify_liveness: verifikasi hidup pakai LiveChecker
            timing_mode: untuk stealth session (jarang dipake di enum)
            threads: paralel worker untuk DNS resolve
            timeout: DNS timeout per query
        """
        self.target       = target_domain.lower().strip()
        # Strip scheme kalau ada
        if self.target.startswith(("http://", "https://")):
            self.target = urlparse(self.target).netloc or self.target
        self.target = self.target.split("/")[0].split(":")[0]

        self.max_subs        = max_subs
        self.do_bruteforce   = bruteforce
        self.do_permutation  = permutation
        self.verify_liveness = verify_liveness
        self.threads         = threads
        self.timeout         = timeout

        self.session      = StealthSession(timing_mode="fast", timeout=15)
        self.live_checker = LiveChecker(timeout=6, threads=min(threads, 10))

        # Hasil per source
        self.found:      set[str] = set()
        self.sources:    dict[str, set] = {
            "crt.sh":      set(),
            "otx":         set(),
            "hackertarget": set(),
            "wayback":     set(),
            "bruteforce":  set(),
            "permutation": set(),
        }

    # =============================================================
    # MAIN ENUM
    # =============================================================
    def enumerate(self) -> dict:
        """
        Jalankan full enumeration pipeline.

        Returns dict:
          all_subdomains, live_subdomains, by_source, live_details, stats
        """
        Logger.section(f"SUBDOMAIN ENUMERATION - {self.target}")

        # === PHASE 1: PASSIVE ===
        Logger.info("Phase 1: Passive enumeration (crt.sh, OTX, HackerTarget)...")
        self._enum_crtsh()
        self._enum_otx()
        self._enum_hackertarget()
        self._enum_wayback()
        Logger.success(f"Passive found: {len(self.found)} subdomains")

        # === PHASE 2: BRUTEFORCE ===
        if self.do_bruteforce and len(self.found) < self.max_subs:
            remaining = self.max_subs - len(self.found)
            Logger.info(f"Phase 2: DNS bruteforce (max {min(len(COMMON_SUBS), remaining)} candidates)...")
            self._enum_bruteforce(limit=remaining)
            Logger.success(f"After bruteforce: {len(self.found)} subdomains")

        # === PHASE 3: PERMUTATION ===
        if self.do_permutation and len(self.found) < self.max_subs:
            Logger.info("Phase 3: Permutation from found subdomains...")
            self._enum_permutation()
            Logger.success(f"After permutation: {len(self.found)} subdomains")

        # Cap total
        if len(self.found) > self.max_subs:
            Logger.warn(f"Capping to max {self.max_subs} subdomains")
            self.found = set(list(self.found)[:self.max_subs])

        # === PHASE 4: LIVENESS ===
        live_details = []
        live_hosts   = []
        if self.verify_liveness and self.found:
            Logger.info(f"Phase 4: Verifying liveness of {len(self.found)} subdomains...")
            live_details = self.live_checker.check_multiple(list(self.found))
            live_hosts   = [d["host"] for d in live_details if d["status"] in ("live", "reachable_empty")]

        Logger.success(
            f"Enumeration complete: {len(self.found)} total, "
            f"{len(live_hosts)} live/reachable"
        )

        return {
            "target":            self.target,
            "all_subdomains":    sorted(self.found),
            "live_subdomains":   sorted(live_hosts),
            "live_details":      live_details,
            "by_source":         {k: sorted(v) for k, v in self.sources.items()},
            "stats": {
                "total_found":       len(self.found),
                "live_count":        sum(1 for d in live_details if d.get("status") == "live"),
                "reachable_empty":   sum(1 for d in live_details if d.get("status") == "reachable_empty"),
                "dns_only":          sum(1 for d in live_details if d.get("status") == "dns_only"),
                "dead":              sum(1 for d in live_details if d.get("status") == "dead"),
                "by_source_counts":  {k: len(v) for k, v in self.sources.items()},
            },
        }

    # =============================================================
    # PASSIVE SOURCES
    # =============================================================
    def _enum_crtsh(self):
        """Certificate Transparency logs via crt.sh."""
        url = f"https://crt.sh/?q=%.{self.target}&output=json"
        try:
            r = requests.get(url, timeout=15,
                             headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code != 200:
                Logger.warn(f"crt.sh returned {r.status_code}")
                return
            data = r.json()
            for entry in data:
                # Kadang name_value berisi banyak SAN (dipisah newline)
                names = entry.get("name_value", "").split("\n")
                for n in names:
                    n = n.strip().lower().lstrip("*.")
                    if self._is_valid_sub(n):
                        self.found.add(n)
                        self.sources["crt.sh"].add(n)
        except (requests.RequestException, json.JSONDecodeError, ValueError) as e:
            Logger.warn(f"crt.sh error: {e}")

    def _enum_otx(self):
        """AlienVault OTX passive DNS."""
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.target}/passive_dns"
        try:
            r = requests.get(url, timeout=15)
            if r.status_code != 200:
                return
            data = r.json()
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "").lower().lstrip("*.")
                if self._is_valid_sub(hostname):
                    self.found.add(hostname)
                    self.sources["otx"].add(hostname)
        except (requests.RequestException, json.JSONDecodeError, ValueError) as e:
            Logger.warn(f"OTX error: {e}")

    def _enum_hackertarget(self):
        """HackerTarget hostsearch API."""
        url = f"https://api.hackertarget.com/hostsearch/?q={self.target}"
        try:
            r = requests.get(url, timeout=15)
            if r.status_code != 200:
                return
            # Format: "hostname,ip" per line
            for line in r.text.splitlines():
                if "," in line:
                    hostname = line.split(",")[0].strip().lower()
                    if self._is_valid_sub(hostname):
                        self.found.add(hostname)
                        self.sources["hackertarget"].add(hostname)
        except requests.RequestException as e:
            Logger.warn(f"HackerTarget error: {e}")

    def _enum_wayback(self):
        """Wayback Machine URL archive."""
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.target}/*&output=json&fl=original&collapse=urlkey&limit=1000"
        try:
            r = requests.get(url, timeout=20)
            if r.status_code != 200:
                return
            data = r.json()
            # First row is header, skip
            for row in data[1:]:
                if not row:
                    continue
                try:
                    parsed = urlparse(row[0])
                    host = parsed.netloc.lower().split(":")[0]
                    if self._is_valid_sub(host):
                        self.found.add(host)
                        self.sources["wayback"].add(host)
                except (IndexError, ValueError):
                    pass
        except (requests.RequestException, json.JSONDecodeError, ValueError) as e:
            Logger.warn(f"Wayback error: {e}")

    # =============================================================
    # BRUTEFORCE
    # =============================================================
    def _enum_bruteforce(self, limit: int = None):
        """DNS bruteforce dengan wordlist common subdomain."""
        wordlist = COMMON_SUBS[:limit] if limit else COMMON_SUBS
        candidates = [f"{w}.{self.target}" for w in wordlist
                      if f"{w}.{self.target}" not in self.found]

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._dns_check, c): c for c in candidates}
            done_count = 0
            total = len(futures)
            for future in as_completed(futures):
                candidate = futures[future]
                try:
                    if future.result():
                        self.found.add(candidate)
                        self.sources["bruteforce"].add(candidate)
                except Exception:
                    pass
                done_count += 1
                # Progress setiap 50
                if done_count % 50 == 0:
                    Logger.info(f"  Bruteforce progress: {done_count}/{total} "
                                f"(found so far: {len(self.sources['bruteforce'])})")

    def _dns_check(self, hostname: str) -> bool:
        """Return True kalau DNS resolve ke IP valid."""
        try:
            socket.setdefaulttimeout(self.timeout)
            _, _, ips = socket.gethostbyname_ex(hostname)
            return bool(ips)
        except (socket.gaierror, socket.timeout, OSError):
            return False
        finally:
            socket.setdefaulttimeout(None)

    # =============================================================
    # PERMUTATION
    # =============================================================
    def _enum_permutation(self):
        """
        Generate variasi dari subdomain yang udah ditemukan.
        Contoh: dari 'api.target.com' -> 'api-v2.target.com',
                'dev-api.target.com', 'api-staging.target.com'
        """
        # Extract subdomain part (bagian sebelum root domain)
        base_subs = set()
        for full in self.found:
            if full == self.target:
                continue
            if full.endswith("." + self.target):
                sub_part = full[:-len("." + self.target)]
                # Ambil komponen pertama saja (misal "api" dari "api.staging")
                if "." not in sub_part:
                    base_subs.add(sub_part)

        # Generate permutations
        candidates = set()
        for base in list(base_subs)[:50]:  # limit permutation base
            for prefix in _PERM_PREFIXES:
                candidates.add(f"{prefix}-{base}.{self.target}")
                candidates.add(f"{prefix}.{base}.{self.target}")
            for suffix in _PERM_SUFFIXES:
                candidates.add(f"{base}-{suffix}.{self.target}")
                candidates.add(f"{base}{suffix}.{self.target}")

        # Filter yang belum ada
        candidates = [c for c in candidates if c not in self.found]

        # Cap sesuai remaining budget
        remaining = self.max_subs - len(self.found)
        candidates = candidates[:remaining]

        if not candidates:
            return

        # DNS check paralel
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._dns_check, c): c for c in candidates}
            for future in as_completed(futures):
                candidate = futures[future]
                try:
                    if future.result():
                        self.found.add(candidate)
                        self.sources["permutation"].add(candidate)
                except Exception:
                    pass

    # =============================================================
    # HELPERS
    # =============================================================
    def _is_valid_sub(self, hostname: str) -> bool:
        """Validasi hostname: harus subdomain dari target."""
        if not hostname:
            return False
        # Harus end dengan target domain
        if hostname != self.target and not hostname.endswith("." + self.target):
            return False
        # Reject karakter aneh
        if not re.match(r"^[a-z0-9.\-]+$", hostname):
            return False
        # Reject wildcard
        if "*" in hostname:
            return False
        return True

    def close(self):
        self.session.close()
        self.live_checker.close()
