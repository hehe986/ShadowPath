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
    def classify_status(self, results):
        public = []
        hidden = []
        sensitive = []

        for item in results:
            url = item.get("url")
            status = item.get("status_code")
            if not url or not status:
                continue

            url_lower = url.lower()

            # 🔴 PRIORITAS 1: sensitive keyword
            if any(k in url_lower for k in self.sensitive_keywords):
                sensitive.append(url)
                continue

            # 🟡 PRIORITAS 2: status-based
            if status == 200:
                public.append(url)
            elif status in [401, 403]:
                hidden.append(url)
            elif status in [301, 302, 307, 308]:
                # redirect — treat as hidden candidate
                hidden.append(url)
            # 🟣 PRIORITAS 3: fallback keyword
            elif any(k in url_lower for k in self.hidden_keywords):
                hidden.append(url)

        return {
            "public": list(set(public)),
            "hidden": list(set(hidden)),
            "sensitive": list(set(sensitive))
        }

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

            # Cek similarity (soft duplicate)
            similar_found = False
            for seen_url, seen_content in [
                (u, i.get("content", ""))
                for i in scan_results
                if i.get("url") in seen_fingerprints.values()
                for u in [i.get("url")]
            ]:
                ratio = self.similarity_ratio(content, seen_content)
                if ratio >= threshold:
                    warnings[url] = (
                        f"⚠️  Response sangat mirip ({ratio:.0%}) dengan: {seen_url}"
                    )
                    similar_found = True
                    break

            if fp:
                seen_fingerprints[fp] = url

            if not similar_found:
                unique.append(url)

        return {
            "unique": unique,
            "duplicates": duplicate_groups,
            "warnings": warnings
        }
