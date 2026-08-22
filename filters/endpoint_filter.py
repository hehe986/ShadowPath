import re
from urllib.parse import urlparse


class EndpointExtractor:
    def __init__(self):
        self.patterns = [
            # Path string biasa: "/api/v1/users"
            r'["\'](/[a-zA-Z0-9_/\-\.]+)["\']',
            # URL lengkap
            r'["\']((https?://)[^"\'<>\s]{5,200})["\']',
            # Route definition: @app.route("/path")
            r'@\w+\.route\(["\']([^"\']+)["\']',
            # Express/Node: app.get("/path", ...)
            r'app\.\w+\(["\']([^"\']+)["\']',
            # Axios/fetch/request call
            r'(?:axios|fetch|request)\s*\.\s*\w+\s*\(["\']([^"\']+)["\']',
            # url: "/path" dalam objek
            r'(?:url|path|endpoint|route)\s*[:=]\s*["\']([^"\']+)["\']',
            # href="/path"
            r'href=["\']([^"\']+)["\']',
            # action="/path"
            r'action=["\']([^"\']+)["\']',
        ]

        # Extension yang tidak relevan untuk endpoint
        self.excluded_extensions = {
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".css", ".woff", ".woff2", ".ttf", ".eot", ".map",
            ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3"
        }

    # =========================
    # 🔹 EXTRACT DARI TEXT
    # =========================
    def extract_from_text(self, text: str) -> list:
        endpoints = set()
        for pattern in self.patterns:
            try:
                matches = re.findall(pattern, text)
                for match in matches:
                    # re.findall bisa return tuple jika ada group
                    ep = match[0] if isinstance(match, tuple) else match
                    ep = ep.strip()
                    if self._is_valid_endpoint(ep):
                        endpoints.add(ep)
            except re.error:
                continue
        return list(endpoints)

    # =========================
    # 🔹 EXTRACT DARI BANYAK FILE (BUG FIX)
    # =========================
    def extract_from_files(self, files_dict: dict) -> list:
        """
        files_dict: {url/path: content_string}
        Bug fix: variabel 'endpoints' sebelumnya tidak didefinisikan.
        """
        results = []  # ✅ Fix: dulu pakai 'endpoints' yang tidak didefinisikan
        for _, content in files_dict.items():
            if content:
                results.extend(self.extract_from_text(content))
        return list(set(results))

    # =========================
    # 🔹 EXTRACT + PASANGKAN KE DOMAIN TARGET
    # =========================
    def extract_and_build(self, files_dict: dict, base_domain: str) -> list:
        """
        Ekstrak endpoint lalu gabungkan dengan domain target.
        Hanya return path relative (bukan URL eksternal lain).

        Returns: list of full URL untuk target domain
        """
        raw = self.extract_from_files(files_dict)
        built = []

        base = base_domain.rstrip("/")
        if not base.startswith("http"):
            base = "https://" + base

        for ep in raw:
            if ep.startswith("/"):
                built.append(base + ep)
            elif ep.startswith("http"):
                # Hanya ambil jika domain sama
                parsed = urlparse(ep)
                target_parsed = urlparse(base)
                if parsed.netloc == target_parsed.netloc:
                    built.append(ep)

        return list(set(built))

    # =========================
    # 🔹 VALIDASI ENDPOINT
    # =========================
    def _is_valid_endpoint(self, ep: str) -> bool:
        if not ep or len(ep) < 2 or len(ep) > 200:
            return False

        # Abaikan fragment
        if ep.startswith("#"):
            return False

        # Abaikan template variable murni
        if ep.startswith("{{") or ep.startswith("${"):
            return False

        # Cek ekstensi file yang tidak relevan
        lower = ep.lower().split("?")[0]
        for ext in self.excluded_extensions:
            if lower.endswith(ext):
                return False

        # Harus dimulai dengan / atau http
        if not (ep.startswith("/") or ep.startswith("http")):
            return False

        return True
