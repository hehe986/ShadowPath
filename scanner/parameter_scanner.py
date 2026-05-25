from core.parameter_extractor import ParameterExtractor
from utils.logger import Logger


class ParameterScanner:
    def __init__(self, extra_keywords: list = None):
        self.extractor = ParameterExtractor()

        # Tambah keyword custom jika ada
        if extra_keywords:
            self.extractor.sensitive_params.extend(extra_keywords)

    # =========================
    # 🚀 MAIN SCAN
    # =========================
    def scan(self, files_dict: dict) -> dict:
        """
        Scan parameter dari source code files.
        files_dict: {filename: content}
        """
        if not files_dict:
            Logger.warn("No files to scan for parameters")
            return self._empty_result()

        Logger.info(f"Scanning parameters from {len(files_dict)} files...")

        # Extract semua parameter
        all_params = self.extractor.extract_from_files(files_dict)
        all_params = list(set(all_params))

        if not all_params:
            Logger.warn("No parameters found")
            return self._empty_result()

        Logger.success(f"Total parameters found: {len(all_params)}")

        # Extract sensitif saja
        sensitive = self.extractor.extract_sensitive(files_dict)
        sensitive = list(set(sensitive))

        # Kategorisasi
        categorized = self._categorize(all_params)

        # Query string template
        qs_template = self.extractor.build_query_string(sensitive or all_params[:10])

        return {
            "total": len(all_params),
            "sensitive": sensitive,
            "by_category": categorized,
            "query_string_template": qs_template,
            "all": all_params,
        }

    # =========================
    # 🔗 SCAN + ATTACH KE ENDPOINTS
    # =========================
    def scan_and_attach(self, files_dict: dict, endpoints: list) -> dict:
        """
        Scan parameter lalu langsung gabungkan ke endpoint list.
        Berguna untuk generate URL siap pakai.
        """
        result = self.scan(files_dict)
        if not result["total"]:
            return result

        # Prioritaskan sensitive, fallback ke semua
        params_to_attach = result["sensitive"] or result["all"][:10]
        attached = self.extractor.attach_to_endpoints(endpoints, params_to_attach)

        result["endpoints_with_params"] = attached
        Logger.success(f"Generated {len(attached)} endpoints with parameters")
        return result

    # =========================
    # 🔍 SCAN DARI LIST LANGSUNG
    # =========================
    def scan_from_urls(self, urls: list) -> dict:
        """
        Extract parameter dari query string URL yang sudah ada.
        Misal: https://target.com/search?q=test&page=1
        """
        from urllib.parse import urlparse, parse_qs

        all_params = set()
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    all_params.update(params.keys())
            except Exception:
                continue

        all_params = list(all_params)
        sensitive = [p for p in all_params
                     if any(k in p.lower() for k in self.extractor.sensitive_params)]

        Logger.info(f"Extracted {len(all_params)} params from {len(urls)} URLs")

        return {
            "total": len(all_params),
            "sensitive": sensitive,
            "by_category": self._categorize(all_params),
            "query_string_template": self.extractor.build_query_string(sensitive or all_params),
            "all": all_params,
        }

    # =========================
    # 🗂️ KATEGORISASI
    # =========================
    def _categorize(self, params: list) -> dict:
        """Pisahkan parameter berdasarkan kategori."""
        categories = {
            "auth":    [],
            "id":      [],
            "file":    [],
            "debug":   [],
            "general": [],
        }

        auth_kw   = {"token", "auth", "password", "passwd", "pwd", "secret",
                     "key", "api_key", "apikey", "session", "jwt", "bearer",
                     "oauth", "credential", "refresh", "access"}
        id_kw     = {"id", "uid", "uuid", "user", "username", "email",
                     "account", "member", "profile"}
        file_kw   = {"file", "path", "dir", "folder", "upload", "download",
                     "attachment", "filename", "filepath"}
        debug_kw  = {"debug", "test", "dev", "verbose", "trace", "log",
                     "mock", "sandbox"}

        for p in params:
            pl = p.lower()
            if any(k in pl for k in auth_kw):
                categories["auth"].append(p)
            elif any(k in pl for k in id_kw):
                categories["id"].append(p)
            elif any(k in pl for k in file_kw):
                categories["file"].append(p)
            elif any(k in pl for k in debug_kw):
                categories["debug"].append(p)
            else:
                categories["general"].append(p)

        return categories

    # =========================
    # 📊 PRINT REPORT
    # =========================
    def print_report(self, result: dict):
        print("\n" + "=" * 50)
        print("  📊 PARAMETER SCAN REPORT")
        print("=" * 50)
        print(f"  Total parameters : {result.get('total', 0)}")
        print(f"  Sensitive        : {len(result.get('sensitive', []))}")

        cats = result.get("by_category", {})
        for cat, params in cats.items():
            if params:
                print(f"\n  [{cat.upper()}]")
                for p in params:
                    marker = " 🔴" if p in result.get("sensitive", []) else ""
                    print(f"    - {p}{marker}")

        if result.get("query_string_template"):
            print(f"\n  Query template:")
            print(f"    {result['query_string_template']}")

        if result.get("endpoints_with_params"):
            print(f"\n  Endpoints with params: {len(result['endpoints_with_params'])}")
        print("=" * 50 + "\n")

    # =========================
    # 🔧 HELPER
    # =========================
    def _empty_result(self) -> dict:
        return {
            "total": 0,
            "sensitive": [],
            "by_category": {"auth": [], "id": [], "file": [], "debug": [], "general": []},
            "query_string_template": "",
            "all": [],
        }
