import requests
import hashlib
import time
import random
import urllib3
from difflib import SequenceMatcher
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class EndpointValidator:
    def __init__(self, timeout=10, delay_range=(1, 2)):
        self.timeout = timeout
        self.delay_range = delay_range
        self.session = requests.Session()

        self.blocked_hosts = [
            "localhost", "127.0.0.1", "0.0.0.0",
            "::1", ".local", "internal", "intranet"
        ]

        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
        ]

        # Cache fingerprint: url -> {fingerprint, content_length, status}
        self._fingerprint_cache = {}

    def _headers(self):
        return {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }

    def _delay(self):
        time.sleep(random.uniform(*self.delay_range))

    # =========================
    # ✅ VALIDASI URL
    # =========================
    def is_valid(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            host = parsed.netloc.lower()
            for blocked in self.blocked_hosts:
                if blocked in host:
                    return False
            if parsed.scheme not in ("http", "https"):
                return False
            return True
        except Exception:
            return False

    # =========================
    # 🌐 SINGLE VALIDATE
    # =========================
    def validate(self, url: str) -> dict | None:
        """
        Validate satu URL dan return detail response.
        Returns: dict {url, status_code, content_length, fingerprint, content, redirect_url}
        """
        if not self.is_valid(url):
            return None

        try:
            self._delay()
            r = self.session.get(
                url,
                headers=self._headers(),
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
            )

            content = r.text
            fp = self._make_fingerprint(content)
            redirect_url = r.url if r.url != url else None

            result = {
                "url": url,
                "status_code": r.status_code,
                "content_length": len(content),
                "fingerprint": fp,
                "content": content[:5000],  # simpan 5000 char untuk comparison
                "redirect_url": redirect_url,
                "headers": dict(r.headers),
            }

            self._fingerprint_cache[url] = {
                "fingerprint": fp,
                "content_length": len(content),
                "status_code": r.status_code,
            }

            return result

        except requests.RequestException:
            return None

    # =========================
    # 🔁 BATCH VALIDATE
    # =========================
    def validate_multiple(self, urls: list) -> list:
        """
        Validate banyak URL sekaligus.
        Returns: list of result dict (hanya yang berhasil)
        """
        results = []
        total = len(urls)
        for i, url in enumerate(urls, 1):
            print(f"[Validator] ({i}/{total}) Checking: {url}")
            result = self.validate(url)
            if result:
                results.append(result)
        return results

    # =========================
    # 🧠 FINGERPRINTING
    # =========================
    def _make_fingerprint(self, content: str) -> str:
        """MD5 dari normalized content."""
        normalized = " ".join(content.split())
        return hashlib.md5(normalized.encode()).hexdigest()

    def _similarity(self, content_a: str, content_b: str) -> float:
        """Similarity ratio antara dua content (0.0 - 1.0)."""
        if not content_a or not content_b:
            return 0.0
        # Batasi untuk performa
        a = content_a[:3000]
        b = content_b[:3000]
        return SequenceMatcher(None, a, b).ratio()

    # =========================
    # 🔍 DUPLICATE DETECTION
    # =========================
    def detect_duplicates(self, results: list, similarity_threshold: float = 0.92) -> dict:
        """
        Analisis hasil validasi untuk deteksi endpoint duplikat/mirip.

        Args:
            results: output dari validate_multiple()
            similarity_threshold: 0.0-1.0, makin tinggi makin ketat

        Returns:
            dict:
              - unique: list URL yang response-nya benar-benar berbeda
              - duplicate_groups: list of list (grup URL dengan response sama)
              - similar_pairs: list of dict {url_a, url_b, similarity}
              - warnings: dict {url: pesan warning}
              - summary: ringkasan statistik
        """
        unique = []
        duplicate_groups = []
        similar_pairs = []
        warnings = {}

        # Index: fingerprint -> url
        fp_index = {}
        # Simpan content untuk similarity check
        processed = []  # list of {url, content, fingerprint}

        for item in results:
            url = item.get("url")
            content = item.get("content", "")
            fp = item.get("fingerprint") or self._make_fingerprint(content)
            status = item.get("status_code")

            if not url:
                continue

            # ── Cek EXACT duplicate via fingerprint ──
            if fp in fp_index:
                original = fp_index[fp]
                warnings[url] = (
                    f"⚠️  [DUPLIKAT IDENTIK] Response sama persis dengan: {original}"
                )
                # Tambah ke grup
                added_to_group = False
                for grp in duplicate_groups:
                    if original in grp:
                        grp.append(url)
                        added_to_group = True
                        break
                if not added_to_group:
                    duplicate_groups.append([original, url])
                continue

            # ── Cek SIMILARITY dengan semua yang sudah diproses ──
            most_similar_url = None
            highest_ratio = 0.0

            for prev in processed:
                ratio = self._similarity(content, prev["content"])
                if ratio > highest_ratio:
                    highest_ratio = ratio
                    most_similar_url = prev["url"]

            if highest_ratio >= similarity_threshold and most_similar_url:
                similar_pairs.append({
                    "url_a": most_similar_url,
                    "url_b": url,
                    "similarity": round(highest_ratio, 4),
                })
                warnings[url] = (
                    f"⚠️  [MIRIP {highest_ratio:.0%}] Response sangat mirip dengan: {most_similar_url}"
                )
            else:
                unique.append(url)

            fp_index[fp] = url
            processed.append({"url": url, "content": content, "fingerprint": fp})

        summary = {
            "total_checked": len(results),
            "unique": len(unique),
            "exact_duplicates": sum(len(g) - 1 for g in duplicate_groups),
            "similar_pairs": len(similar_pairs),
            "duplicate_groups": len(duplicate_groups),
        }

        return {
            "unique": unique,
            "duplicate_groups": duplicate_groups,
            "similar_pairs": similar_pairs,
            "warnings": warnings,
            "summary": summary,
        }

    # =========================
    # 📊 PRINT REPORT
    # =========================
    def print_duplicate_report(self, analysis: dict):
        s = analysis.get("summary", {})
        print("\n" + "=" * 55)
        print("  📊 DUPLICATE ANALYSIS REPORT")
        print("=" * 55)
        print(f"  Total diperiksa  : {s.get('total_checked', 0)}")
        print(f"  ✅ Unik          : {s.get('unique', 0)}")
        print(f"  🔴 Duplikat identik: {s.get('exact_duplicates', 0)}")
        print(f"  🟡 Pasangan mirip : {s.get('similar_pairs', 0)}")
        print("=" * 55)

        if analysis.get("duplicate_groups"):
            print("\n  🔴 GRUP DUPLIKAT IDENTIK:")
            for i, grp in enumerate(analysis["duplicate_groups"], 1):
                print(f"  Grup {i}:")
                for url in grp:
                    print(f"    - {url}")

        if analysis.get("similar_pairs"):
            print("\n  🟡 PASANGAN MIRIP:")
            for pair in analysis["similar_pairs"]:
                print(f"  [{pair['similarity']:.0%}] {pair['url_a']}")
                print(f"        └─ {pair['url_b']}")

        if analysis.get("warnings"):
            print("\n  ⚠️  WARNINGS:")
            for url, msg in analysis["warnings"].items():
                print(f"  {msg}")
                print(f"    URL: {url}")
        print("=" * 55 + "\n")
