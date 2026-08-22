"""
core/live_checker.py — Domain & Subdomain Liveness Verification
================================================================
Verifikasi apakah domain/subdomain benar-benar aktif dan punya konten,
BUKAN cuma DNS record kosong atau parking page.

Empat tingkat status:
  DEAD             — DNS tidak resolve, atau connection refused
  DNS_ONLY         — DNS resolve tapi tidak ada HTTP server responsive
  REACHABLE_EMPTY  — HTTP respond tapi konten kosong/parking/default page
  LIVE             — HTTP respond dengan konten nyata (aplikasi berjalan)

Deteksi parking page & default landing:
  - Content length terlalu kecil (< threshold)
  - Fingerprint cocok dengan default Nginx/Apache/IIS/cPanel
  - Keyword parking: "domain for sale", "coming soon", "default page"
  - Redirect ke registrar (godaddy, namecheap, sedo, dll)
"""

import socket
import ipaddress
import re
import hashlib
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.stealth import StealthSession
from utils.logger import Logger


# =============================================================
# 🏷️ STATUS CONSTANTS
# =============================================================
STATUS_DEAD            = "dead"
STATUS_DNS_ONLY        = "dns_only"
STATUS_REACHABLE_EMPTY = "reachable_empty"
STATUS_LIVE            = "live"


# =============================================================
# 🚧 PARKING / DEFAULT PAGE SIGNATURES
# =============================================================
_PARKING_KEYWORDS = [
    "domain for sale", "domain is for sale", "buy this domain",
    "coming soon", "under construction", "site not configured",
    "default web site page", "welcome to nginx", "apache2 ubuntu default",
    "it works!", "welcome to centos", "test page for the",
    "this domain may be for sale", "parked domain", "domain parking",
    "future home of something", "hosting provider",
    "sedo", "godaddy parking", "namecheap parking", "hugedomains",
    "afternic", "dan.com", "domainmarket",
    "cpanel", "plesk default page",
    "index of /", "directory listing for /",
]

# Redirect ke domain-domain registrar/parking
_PARKING_REDIRECT_HOSTS = {
    "sedo.com", "sedoparking.com", "hugedomains.com", "dan.com",
    "afternic.com", "godaddy.com", "namecheap.com", "domainmarket.com",
    "parkingcrew.net", "bodis.com", "above.com",
}

# Fingerprint MD5 dari default page yang paling umum
# (dibuat dari 500 char pertama konten yang di-normalize)
_KNOWN_DEFAULT_FINGERPRINTS: set[str] = set()

# Ukuran konten minimum untuk dianggap "punya isi nyata"
_MIN_CONTENT_LENGTH = 500


# =============================================================
# 🔍 DNS RESOLVER
# =============================================================
def resolve_dns(host: str, timeout: float = 3.0) -> list[str] | None:
    """
    Resolve DNS untuk hostname.
    Returns list of IP addresses (A records), atau None jika tidak resolve.
    """
    socket.setdefaulttimeout(timeout)
    try:
        _, _, ips = socket.gethostbyname_ex(host)
        # Filter IP invalid (0.0.0.0, private range untuk target publik, dll)
        valid = []
        for ip in ips:
            try:
                addr = ipaddress.ip_address(ip)
                # Skip 0.0.0.0 dan loopback
                if addr.is_unspecified or addr.is_loopback:
                    continue
                valid.append(ip)
            except ValueError:
                continue
        return valid if valid else None
    except (socket.gaierror, socket.timeout, OSError):
        return None
    finally:
        socket.setdefaulttimeout(None)


# =============================================================
# 🕵️ LIVE CHECKER
# =============================================================
class LiveChecker:
    """
    Cek apakah domain/subdomain benar-benar aktif dan punya konten nyata.
    """

    def __init__(self,
                 timing_mode: str = "fast",
                 timeout: int = 8,
                 threads: int = 5,
                 min_content_length: int = _MIN_CONTENT_LENGTH):
        """
        Args:
            timing_mode: "fast" untuk liveness check (default, aman)
            timeout: HTTP timeout per host
            threads: paralel worker untuk cek banyak host
            min_content_length: konten di bawah ini dianggap kosong
        """
        self.timeout            = timeout
        self.threads            = threads
        self.min_content_length = min_content_length
        # Gunakan StealthSession supaya cek pun tidak mencolok
        self.session = StealthSession(
            timing_mode=timing_mode,
            timeout=timeout,
            interleave=False,   # jangan interleave saat cek liveness
        )

    # =============================================================
    # 🎯 CEK SATU HOST
    # =============================================================
    def check_host(self, host: str) -> dict:
        """
        Cek satu hostname secara lengkap.

        Returns dict:
          host, status, ips, http_status, https_status, content_length,
          fingerprint, title, server, reason
        """
        result = {
            "host":           host,
            "status":         STATUS_DEAD,
            "ips":            [],
            "http_status":    None,
            "https_status":   None,
            "content_length": 0,
            "fingerprint":    "",
            "title":          "",
            "server":         "",
            "reason":         "",
            "final_url":      "",
            "headers":        {},
            "content":        "",
        }

        # ── STEP 1: DNS ──
        ips = resolve_dns(host, timeout=3.0)
        if not ips:
            result["reason"] = "DNS resolution failed"
            return result

        result["ips"] = ips

        # ── STEP 2: HTTP PROBE (HTTPS dulu, fallback HTTP) ──
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            probe = self.session.get(url, skip_delay=False)

            if not probe:
                continue

            status = probe.get("status_code")
            result[f"{scheme}_status"] = status

            # Connection error atau timeout
            if status is None:
                continue

            # Ada response — analisis konten
            content   = probe.get("content", "")
            length    = probe.get("content_length", 0)
            fp        = probe.get("fingerprint", "")
            final_url = probe.get("redirect_url") or url

            result["content_length"] = length
            result["fingerprint"]    = fp
            result["server"]         = probe.get("server", "")
            result["final_url"]      = final_url
            result["headers"]        = probe.get("headers", {})
            result["content"]        = content

            # Extract title
            title_match = re.search(r'<title[^>]*>(.*?)</title>',
                                     content, re.IGNORECASE | re.DOTALL)
            if title_match:
                result["title"] = title_match.group(1).strip()[:120]

            # ── STEP 3: KLASIFIKASI ──
            classification = self._classify_response(
                status=status,
                content=content,
                length=length,
                final_url=final_url,
                original_host=host,
            )
            result["status"] = classification["status"]
            result["reason"] = classification["reason"]

            # HTTPS berhasil, tidak perlu coba HTTP
            if scheme == "https" and status:
                return result

        # Kalau sampai sini, DNS resolve tapi HTTP semua gagal
        if result["status"] == STATUS_DEAD and result["ips"]:
            result["status"] = STATUS_DNS_ONLY
            result["reason"] = "DNS resolve but no HTTP response"

        return result

    # =============================================================
    # 🧠 KLASIFIKASI RESPONSE
    # =============================================================
    def _classify_response(self, status: int, content: str, length: int,
                           final_url: str, original_host: str) -> dict:
        """
        Klasifikasi response ke salah satu STATUS_*.

        Logika:
          - 5xx murni tanpa konten aplikasi → DNS_ONLY (server ada tapi rusak)
          - 4xx (401/403) DENGAN konten meaningful → LIVE (aplikasi ada, auth-gated)
          - 4xx generic 404 → REACHABLE_EMPTY
          - 2xx/3xx dengan konten parking → REACHABLE_EMPTY
          - 2xx/3xx dengan konten nyata → LIVE
        """
        content_lower = content.lower()

        # ── Cek redirect ke parking domain ──
        try:
            final_host = urlparse(final_url).netloc.lower().split(":")[0]
            for parking in _PARKING_REDIRECT_HOSTS:
                if parking in final_host and parking not in original_host:
                    return {
                        "status": STATUS_REACHABLE_EMPTY,
                        "reason": f"Redirect ke parking domain: {final_host}",
                    }
        except Exception:
            pass

        # ── Cek parking keywords ──
        for kw in _PARKING_KEYWORDS:
            if kw in content_lower:
                return {
                    "status": STATUS_REACHABLE_EMPTY,
                    "reason": f"Parking/default page terdeteksi: '{kw}'",
                }

        # ── Cek fingerprint default page ──
        if self.session and length < 3000:
            fp_short = hashlib.md5(
                " ".join(content[:1000].split()).encode()
            ).hexdigest()
            if fp_short in _KNOWN_DEFAULT_FINGERPRINTS:
                return {
                    "status": STATUS_REACHABLE_EMPTY,
                    "reason": "Fingerprint cocok dengan default page",
                }

        # ── Status code analysis ──
        # 5xx server error
        if 500 <= status < 600:
            if length < 200:
                return {
                    "status": STATUS_DNS_ONLY,
                    "reason": f"Server error {status} tanpa konten",
                }
            return {
                "status": STATUS_REACHABLE_EMPTY,
                "reason": f"Server error {status}",
            }

        # 4xx: bedakan aplikasi auth-gated (LIVE) vs 404 generic (EMPTY)
        if 400 <= status < 500:
            # 401/403 dengan konten yang mengandung indikator aplikasi = LIVE
            app_indicators = ["login", "sign in", "unauthorized", "forbidden",
                              "authentication", "api", "token", "session"]
            has_app_content = any(ind in content_lower for ind in app_indicators)

            if status in (401, 403) and (has_app_content or length > 500):
                return {
                    "status": STATUS_LIVE,
                    "reason": f"Aplikasi aktif ({status} - auth-gated)",
                }

            # 404 dengan konten sangat sedikit
            if length < self.min_content_length:
                return {
                    "status": STATUS_REACHABLE_EMPTY,
                    "reason": f"HTTP {status} dengan konten minimal",
                }

            # 404 tapi ada konten cukup — mungkin custom 404 page dari aplikasi
            return {
                "status": STATUS_LIVE,
                "reason": f"Custom {status} page dari aplikasi",
            }

        # 2xx / 3xx dengan konten sangat sedikit
        if length < self.min_content_length:
            return {
                "status": STATUS_REACHABLE_EMPTY,
                "reason": f"Response {status} dengan konten minimal ({length} bytes)",
            }

        # Semua check lolos — ini live
        return {
            "status": STATUS_LIVE,
            "reason": f"Live application ({status}, {length} bytes)",
        }

    # =============================================================
    # 🔁 BATCH CHECK
    # =============================================================
    def check_multiple(self, hosts: list) -> list[dict]:
        """
        Cek banyak host secara paralel dengan thread pool.
        Returns list of result dict.
        """
        results = []
        hosts = list(set(hosts))
        total = len(hosts)

        Logger.info(f"Checking liveness of {total} hosts (threads={self.threads})...")

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            future_map = {pool.submit(self.check_host, h): h for h in hosts}
            done_count = 0
            for future in as_completed(future_map):
                host = future_map[future]
                try:
                    r = future.result()
                except Exception as e:
                    r = {
                        "host":   host,
                        "status": STATUS_DEAD,
                        "reason": f"Exception: {e}",
                    }

                results.append(r)
                done_count += 1

                # Log inline
                status_icon = {
                    STATUS_LIVE:            "🟢",
                    STATUS_REACHABLE_EMPTY: "⚪",
                    STATUS_DNS_ONLY:        "🟡",
                    STATUS_DEAD:            "🔴",
                }.get(r["status"], "❓")

                Logger.info(
                    f"  [{done_count}/{total}] {status_icon} {host:<40} "
                    f"→ {r['status']:<16} ({r.get('reason', '')[:60]})"
                )

        return results

    # =============================================================
    # 📊 GROUPING
    # =============================================================
    @staticmethod
    def group_by_status(results: list[dict]) -> dict:
        """Kelompokkan hasil berdasarkan status."""
        groups = {
            STATUS_LIVE:            [],
            STATUS_REACHABLE_EMPTY: [],
            STATUS_DNS_ONLY:        [],
            STATUS_DEAD:            [],
        }
        for r in results:
            groups[r["status"]].append(r)
        return groups

    @staticmethod
    def live_hosts_only(results: list[dict]) -> list[str]:
        """Return hanya hostname yang benar-benar LIVE."""
        return [r["host"] for r in results if r["status"] == STATUS_LIVE]

    def close(self):
        self.session.close()
