import re
from urllib.parse import urlparse, parse_qs


class EndpointFilter:
    def __init__(self):
        # Ekstensi file statis yang tidak relevan
        self.blacklist_ext = {
            ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff",
            ".css", ".scss", ".less",
            ".svg", ".woff", ".woff2", ".ttf", ".eot", ".otf",
            ".ico", ".cur",
            ".mp4", ".mp3", ".avi", ".mov", ".webm", ".ogg", ".wav",
            ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
            ".map",  # source map
        }

        # Path yang tidak relevan untuk pentesting
        self.blacklist_paths = {
            "/favicon.ico", "/robots.txt", "/sitemap.xml",
            "/ads.txt", "/security.txt", "/.well-known",
        }

        # Keyword yang menandakan endpoint menarik dari sisi security
        self.interesting_keywords = [
            "api", "admin", "auth", "login", "logout", "register",
            "token", "key", "secret", "password", "reset", "forgot",
            "upload", "download", "file", "export", "import",
            "user", "account", "profile", "setting", "config",
            "debug", "test", "dev", "internal", "private", "hidden",
            "dashboard", "panel", "manage", "console", "control",
            "search", "query", "graphql", "grpc", "rpc", "soap",
            "webhook", "callback", "redirect", "oauth", "sso",
            "backup", "log", "report", "data", "database", "db",
            "v1", "v2", "v3",  # API versioning
        ]

        self.min_length = 3

    # =========================
    # ✅ VALIDASI DASAR
    # =========================
    def is_valid(self, endpoint: str) -> bool:
        ep = endpoint.strip().lower()

        if len(ep) < self.min_length:
            return False

        # Ekstensi statis
        path = urlparse(ep).path if ep.startswith("http") else ep
        path_no_query = path.split("?")[0]
        for ext in self.blacklist_ext:
            if path_no_query.endswith(ext):
                return False

        # Path blacklist
        for bl in self.blacklist_paths:
            if path_no_query == bl:
                return False

        # Abaikan template / placeholder
        if re.search(r'\{\{|\$\{|<%=', ep):
            return False

        # Harus ada karakter alfanumerik
        if not re.search(r'[a-zA-Z0-9]', ep):
            return False

        # Filter ViewState / base64 junk:
        # segment path yang sangat panjang (>60 char) tanpa titik/slash internal
        # dan campuran acak huruf besar-kecil+angka = kemungkinan besar token,
        # bukan endpoint asli (misal __VIEWSTATE ASP.NET yang ke-parse jadi URL).
        last_segment = path_no_query.rstrip("/").split("/")[-1]
        if len(last_segment) > 60:
            # Hitung rasio karakter "acak" (base64-like tanpa ekstensi file)
            has_ext = "." in last_segment[-6:]  # ada ekstensi di ujung?
            if not has_ext and re.match(r'^[a-zA-Z0-9+/=_-]+$', last_segment):
                return False

        return True

    # =========================
    # 🔍 FILTER LIST
    # =========================
    def filter(self, endpoints: list) -> list:
        results = []
        for ep in endpoints:
            if self.is_valid(ep):
                results.append(ep)
        return list(set(results))

    # =========================
    # 🎯 FILTER + SCORING (PRIORITAS)
    # =========================
    def filter_and_score(self, endpoints: list) -> list:
        """
        Filter endpoint dan beri skor berdasarkan potensi security interest.
        Return list diurutkan dari skor tertinggi.

        Score per item:
          +2 per interesting keyword
          +1 jika ada query parameter
          +1 jika path lebih dari 2 segment
          -1 jika path terlalu generik (/, /index, /home)
        """
        scored = []
        generic_paths = {"/", "/index", "/home", "/index.html", "/index.php"}

        for ep in endpoints:
            if not self.is_valid(ep):
                continue

            score = 0
            ep_lower = ep.lower()

            # Keyword menarik
            for kw in self.interesting_keywords:
                if kw in ep_lower:
                    score += 2

            # Ada query parameter
            try:
                parsed = urlparse(ep)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    score += len(params)  # +1 per parameter

                # Path depth
                path_parts = [p for p in parsed.path.split("/") if p]
                if len(path_parts) > 2:
                    score += 1

                # Generik
                if parsed.path in generic_paths:
                    score -= 1

            except Exception:
                pass

            scored.append({"endpoint": ep, "score": score})

        # Sort by score descending
        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored

    # =========================
    # 🔴 FILTER HANYA YANG MENARIK
    # =========================
    def filter_interesting(self, endpoints: list, min_score: int = 2) -> list:
        """Return hanya endpoint dengan score >= min_score."""
        scored = self.filter_and_score(endpoints)
        return [item["endpoint"] for item in scored if item["score"] >= min_score]

    # =========================
    # 🧹 NORMALISASI & DEDUP
    # =========================
    def normalize(self, endpoint: str) -> str:
        """Normalisasi endpoint: lowercase path, buang trailing slash."""
        ep = endpoint.strip()
        if ep.startswith("http"):
            try:
                parsed = urlparse(ep)
                path = parsed.path.rstrip("/") or "/"
                normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
                if parsed.query:
                    normalized += f"?{parsed.query}"
                return normalized
            except Exception:
                return ep
        return ep.rstrip("/") or "/"

    def deduplicate(self, endpoints: list) -> list:
        """
        Deduplikasi dengan normalisasi — /api/v1/ dan /api/v1 dianggap sama.
        """
        seen = set()
        unique = []
        for ep in endpoints:
            norm = self.normalize(ep)
            if norm not in seen:
                seen.add(norm)
                unique.append(ep)
        return unique

    # =========================
    # 🔗 SEPARATE BY TYPE
    # =========================
    def separate_by_type(self, endpoints: list) -> dict:
        """
        Pisahkan endpoint berdasarkan tipe:
          - api: mengandung /api/, /v1/, /v2/, graphql, dll
          - auth: login, logout, register, oauth, dll
          - file: upload, download, export, dll
          - admin: admin, panel, dashboard, dll
          - other: sisanya
        """
        categories = {
            "api": [],
            "auth": [],
            "file": [],
            "admin": [],
            "other": [],
        }

        api_kw = {"api", "v1", "v2", "v3", "graphql", "grpc", "rpc", "rest", "soap", "webhook"}
        auth_kw = {"login", "logout", "register", "auth", "oauth", "sso", "token", "session", "2fa", "mfa", "forgot", "reset", "verify"}
        file_kw = {"upload", "download", "export", "import", "file", "attachment", "media", "storage", "backup"}
        admin_kw = {"admin", "panel", "dashboard", "console", "manage", "management", "control", "staff", "superuser", "backoffice"}

        for ep in endpoints:
            if not self.is_valid(ep):
                continue
            ep_lower = ep.lower()

            if any(k in ep_lower for k in admin_kw):
                categories["admin"].append(ep)
            elif any(k in ep_lower for k in auth_kw):
                categories["auth"].append(ep)
            elif any(k in ep_lower for k in file_kw):
                categories["file"].append(ep)
            elif any(k in ep_lower for k in api_kw):
                categories["api"].append(ep)
            else:
                categories["other"].append(ep)

        # Deduplikasi per kategori
        for k in categories:
            categories[k] = self.deduplicate(categories[k])

        return categories

    # =========================
    # 📊 FILTER WITH STATS
    # =========================
    def filter_with_stats(self, endpoints: list) -> dict:
        """Filter dan kembalikan statistik lengkap."""
        valid = self.filter(endpoints)
        deduped = self.deduplicate(valid)
        by_type = self.separate_by_type(deduped)
        scored = self.filter_and_score(deduped)

        return {
            "endpoints": deduped,
            "by_type": by_type,
            "scored": scored[:20],  # top 20
            "summary": {
                "total_input": len(endpoints),
                "after_filter": len(valid),
                "after_dedup": len(deduped),
                "api": len(by_type["api"]),
                "auth": len(by_type["auth"]),
                "file": len(by_type["file"]),
                "admin": len(by_type["admin"]),
                "other": len(by_type["other"]),
            }
        }
