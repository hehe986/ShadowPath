import re


class ParameterExtractor:
    def __init__(self):
        self.patterns = [
            # Query string: ?param=value atau &param=value
            r'[?&]([a-zA-Z0-9_\-]{2,30})=',
            # JSON key: "param_name": atau 'param_name':
            r'"([a-zA-Z0-9_\-]{2,30})"\s*:',
            # Variable assignment: param_name =
            r'\b([a-zA-Z0-9_]{3,30})\s*=\s*["\'][^"\']{1,100}["\']',
            # Form input name: name="param"
            r'name=["\']([a-zA-Z0-9_\-]{2,30})["\']',
            # Python/JS function keyword args: func(param=value)
            r'\b([a-zA-Z0-9_]{3,20})\s*=(?!=)',
            # request.args.get("param") / req.query.param
            r'(?:args|query|params|body|form)\s*[\.\[]\s*["\']([a-zA-Z0-9_\-]{2,30})["\']',
        ]

        # Blacklist: kata umum yang bukan parameter API
        self.blacklist = {
            "true", "false", "null", "none", "undefined", "return", "import",
            "class", "def", "var", "let", "const", "function", "if", "else",
            "for", "while", "this", "self", "type", "new", "from", "as",
            "and", "or", "not", "in", "is", "try", "except", "with",
            "print", "echo", "break", "continue", "pass", "super",
            "async", "await", "static", "public", "private", "protected",
            "string", "integer", "boolean", "object", "array", "list",
        }

        # Keyword parameter yang menarik dari sudut pandang security
        self.sensitive_params = [
            "token", "key", "api_key", "apikey", "secret", "password",
            "passwd", "pwd", "auth", "access", "credential", "session",
            "jwt", "bearer", "refresh", "id", "user", "username", "email",
            "redirect", "url", "callback", "next", "return_url", "file",
            "path", "cmd", "exec", "query", "search", "debug", "admin",
        ]

    # =========================
    # 🔹 EXTRACT DARI TEXT
    # =========================
    def extract_from_text(self, text: str) -> list:
        params = set()
        for pattern in self.patterns:
            try:
                matches = re.findall(pattern, text)
                for match in matches:
                    p = match.strip().lower()
                    if self._is_valid_param(p):
                        params.add(p)
            except re.error:
                continue
        return list(params)

    # =========================
    # 🔹 EXTRACT DARI BANYAK FILE
    # =========================
    def extract_from_files(self, files_dict: dict) -> list:
        results = []
        for _, content in files_dict.items():
            if content:
                results.extend(self.extract_from_text(content))
        return list(set(results))

    # =========================
    # 🔴 EXTRACT PARAMETER SENSITIF
    # =========================
    def extract_sensitive(self, files_dict: dict) -> list:
        """Return hanya parameter yang tergolong sensitif/menarik."""
        all_params = self.extract_from_files(files_dict)
        return [p for p in all_params if any(s in p for s in self.sensitive_params)]

    # =========================
    # 🔗 BUILD QUERY STRING
    # =========================
    def build_query_string(self, params: list, placeholder: str = "FUZZ") -> str:
        """
        Buat query string dari list parameter.
        Contoh: ?token=FUZZ&id=FUZZ&redirect=FUZZ
        """
        if not params:
            return ""
        return "?" + "&".join(f"{p}={placeholder}" for p in params)

    # =========================
    # 🔗 ATTACH PARAMS KE URLS
    # =========================
    def attach_to_endpoints(self, endpoints: list, params: list) -> list:
        """
        Gabungkan endpoint dengan parameter yang ditemukan.
        Returns list of URL dengan query string.
        """
        if not params:
            return endpoints

        qs = self.build_query_string(params)
        result = []
        for ep in endpoints:
            if "?" not in ep:
                result.append(ep + qs)
            else:
                result.append(ep)
        return result

    # =========================
    # ✅ VALIDASI PARAMETER
    # =========================
    def _is_valid_param(self, param: str) -> bool:
        if not param:
            return False
        if len(param) < 2 or len(param) > 30:
            return False
        if param in self.blacklist:
            return False
        # Harus mengandung huruf
        if not re.search(r'[a-zA-Z]', param):
            return False
        # Tidak boleh diawali angka
        if param[0].isdigit():
            return False
        return True
