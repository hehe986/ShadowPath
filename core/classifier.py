import hashlib
from difflib import SequenceMatcher


class EndpointClassifier:
    def __init__(self, hidden_keywords=None, sensitive_keywords=None):
        self.hidden_keywords = hidden_keywords or [
            "admin", "internal", "private", "dashboard", "panel",
            "manage", "management", "control", "console", "portal",
            "backend", "backoffice", "staff", "superuser", "root"
        ]
        self.sensitive_keywords = sensitive_keywords or [
            "login", "auth", "token", "apikey", "password", "secret",
            "credential", "oauth", "jwt", "session", "key", "reset",
            "forgot", "register", "signup", "2fa", "mfa", "verify"
        ]

    # =========================
    # 🔹 KEYWORD CLASSIFICATION (OSINT)
    # =========================
    def classify(self, endpoint):
        ep = endpoint.lower()
        for k in self.sensitive_keywords:
            if k in ep:
                return "sensitive"
        for k in self.hidden_keywords:
            if k in ep:
                return "hidden"
        return "public"

    def classify_list(self, endpoints):
        results = {
            "public": [],
            "hidden": [],
            "sensitive": []
        }
        for ep in endpoints:
            category = self.classify(ep)
            results[category].append(ep)
        for k in results:
            results[k] = list(set(results[k]))
        return results

    # =========================
    # 🔥 STATUS CODE CLASSIFICATION (ACTIVE SCAN)
    # =========================
    def _is_error_page(self, body: str) -> bool:
        """
        Deteksi soft-error: body yang isinya halaman error server walau status 200.
        Return True kalau body kelihatan seperti error/maintenance page.

        Cek hanya pada body pendek (halaman error biasanya ringkas). Halaman
        asli yang panjang jarang cocok karena pola dicek di awal konten.
        """
        if not body:
            return False

        # Ambil potongan awal (halaman error biasanya menaruh pesan di awal)
        head = body[:2000]

        error_signatures = [
            "service unavailable",
            "503 service",
            "temporarily unable to service",
            "maintenance downtime",
            "under maintenance",
            "site is temporarily unavailable",
            "500 internal server error",
            "502 bad gateway",
            "504 gateway timeout",
            "database connection error",
            "error establishing a database connection",
            "account suspended",
            "this site can't be reached",
            "application error",
        ]
        # Minimal 1 signature match DAN body relatif pendek (ciri error page)
        matched = any(sig in head for sig in error_signatures)
        if matched and len(body) < 3000:
            return True
        # Signature kuat (eksplisit maintenance) → error walau body agak panjang
        strong = ("temporarily unable to service" in head or
                  "error establishing a database connection" in head)
        return strong

    def classify_status(self, results):
        """
        Klasifikasi 4-way berdasar kombinasi:
          - sifat endpoint (public umum vs private/hidden) → dari keyword
          - aksesibilitas (terbuka vs tertutup) → dari HTTP status

        Kategori:
          public_open     — endpoint umum, bisa diakses (200)
          public_closed   — endpoint umum, tapi terkunci (401/403/404)
          private_open    — endpoint hidden/sensitive, tapi TERBUKA (200) ⚠️ paling menarik
          private_closed  — endpoint hidden/sensitive, tertutup (401/403)

        Legacy keys 'public', 'hidden', 'sensitive' tetap dipertahankan
        untuk backward compat dengan output formatter yang sudah ada.
        """
        public_open     = []
        public_closed   = []
        private_open    = []
        private_closed  = []

        # Legacy buckets
        public          = []
        hidden          = []
        sensitive       = []

        for item in results:
            url = item.get("url")
            status = item.get("status_code")
            if not url:
                continue

            url_lower = url.lower()
            body = (item.get("content") or item.get("body") or "").lower()

            # ── STEP 0: Deteksi soft-error ──
            # Sebagian server balikin status 200 tapi body-nya halaman error
            # (503 maintenance, "service unavailable", dll). Ini bukan endpoint
            # yang beneran terbuka — perlakukan sebagai closed/skip supaya tidak
            # jadi false positive di private_open.
            if body and self._is_error_page(body):
                # endpoint ada tapi lagi error → closed (bukan open)
                is_sensitive = any(k in url_lower for k in self.sensitive_keywords)
                is_hidden    = any(k in url_lower for k in self.hidden_keywords)
                if is_sensitive or is_hidden:
                    private_closed.append(url)
                else:
                    public_closed.append(url)
                continue

            # ── STEP 1: Tentukan sifat endpoint (public vs private) ──
            is_sensitive = any(k in url_lower for k in self.sensitive_keywords)
            is_hidden    = any(k in url_lower for k in self.hidden_keywords)
            is_private   = is_sensitive or is_hidden

            # ── STEP 2: Tentukan aksesibilitas (open vs closed) ──
            if status == 200 or status in (201, 204):
                accessible = "open"
            elif status in (401, 403):
                accessible = "closed"
            elif status in (301, 302, 307, 308):
                # Redirect — cek redirect_url apakah menuju login page
                # Default: treat sebagai closed (kemungkinan besar redirect ke login)
                accessible = "closed"
            elif status in (404, 405):
                accessible = "closed"  # tidak ada / tidak diizinkan
            else:
                # 5xx atau status lain — skip (tidak konklusif)
                continue

            # ── STEP 3: Isi 4-way bucket ──
            if is_private and accessible == "open":
                private_open.append(url)
                sensitive.append(url) if is_sensitive else hidden.append(url)
            elif is_private and accessible == "closed":
                private_closed.append(url)
                sensitive.append(url) if is_sensitive else hidden.append(url)
            elif not is_private and accessible == "open":
                public_open.append(url)
                public.append(url)
            elif not is_private and accessible == "closed":
                public_closed.append(url)
                # legacy: closed public tidak masuk 'public' bucket

        # Dedup + return
        result = {
            # 4-way classification (baru)
            "public_open":    list(set(public_open)),
            "public_closed":  list(set(public_closed)),
            "private_open":   list(set(private_open)),
            "private_closed": list(set(private_closed)),

            # Legacy 3-way (untuk backward compat)
            "public":         list(set(public)),
            "hidden":         list(set(hidden)),
            "sensitive":      list(set(sensitive)),
        }
        return result

    # =========================
    # 🧠 RESPONSE FINGERPRINTING
    # =========================
    def fingerprint(self, content: str) -> str:
        """Generate fingerprint dari response content."""
        if not content:
            return ""
        normalized = " ".join(content.split())
        return hashlib.md5(normalized.encode()).hexdigest()

    def similarity_ratio(self, content_a: str, content_b: str) -> float:
        """Hitung similarity antara dua response (0.0 - 1.0)."""
        if not content_a or not content_b:
            return 0.0
        return SequenceMatcher(None, content_a[:3000], content_b[:3000]).ratio()

    # =========================
    # 🔍 DUPLICATE / SIMILAR ENDPOINT DETECTION
    # =========================
    def detect_duplicates(self, scan_results: list, threshold: float = 0.92) -> dict:
        """
        Deteksi endpoint yang memiliki response mirip/sama.

        Args:
            scan_results: list of dict {url, status_code, content, fingerprint}
            threshold: angka 0-1, makin tinggi makin ketat (default 0.92)

        Returns:
            dict berisi:
              - unique: endpoint yang benar-benar berbeda
              - duplicates: list grup endpoint yang response-nya sama
              - warnings: pesan warning per endpoint
        """
        unique = []
        duplicate_groups = []
        warnings = {}
        seen_fingerprints = {}  # fingerprint -> url pertama
        # BUG FIX: tambah 'processed' list untuk similarity check yang bersih.
        # Sebelumnya, loop similarity ambil content dari scan_results berdasarkan
        # seen_fingerprints.values() — logic ini bergantung pada state dict yang
        # berubah mid-loop dan variabel 'processed' tidak pernah didefinisikan
        # sehingga NameError. Ganti dengan list eksplisit yang diisi setelah
        # setiap item selesai diproses.
        processed = []  # list of {url, content} yang sudah diproses

        for item in scan_results:
            url = item.get("url")
            content = item.get("content", "")
            fp = item.get("fingerprint") or self.fingerprint(content)

            if not url:
                continue

            # Cek exact duplicate via fingerprint
            if fp and fp in seen_fingerprints:
                original = seen_fingerprints[fp]
                # Cari atau buat grup
                added = False
                for grp in duplicate_groups:
                    if original in grp:
                        grp.append(url)
                        added = True
                        break
                if not added:
                    duplicate_groups.append([original, url])

                warnings[url] = (
                    f"⚠️  Response IDENTIK dengan: {original}"
                )
                continue

            # Cek similarity (soft duplicate) — bandingkan dengan semua item
            # yang sudah selesai diproses, bukan seluruh scan_results sekaligus.
            similar_found = False
            for prev in processed:
                ratio = self.similarity_ratio(content, prev.get("content", ""))
                if ratio >= threshold:
                    warnings[url] = (
                        f"⚠️  Response sangat mirip ({ratio:.0%}) dengan: {prev['url']}"
                    )
                    similar_found = True
                    break

            if fp:
                seen_fingerprints[fp] = url

            # Tambah ke processed setelah semua check selesai
            processed.append({"url": url, "content": content})

            if not similar_found:
                unique.append(url)

        return {
            "unique": unique,
            "duplicates": duplicate_groups,
            "warnings": warnings
        }
