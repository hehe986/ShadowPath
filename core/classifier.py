class EndpointClassifier:

    def __init__(self, hidden_keywords=None, sensitive_keywords=None):

        self.hidden_keywords = hidden_keywords or [
            "admin", "internal", "private", "dashboard", "panel"
        ]

        self.sensitive_keywords = sensitive_keywords or [
            "login", "auth", "token", "apikey", "password"
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

        # remove duplicate
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

            # 🟣 PRIORITAS 3: fallback keyword
            elif any(k in url_lower for k in self.hidden_keywords):
                hidden.append(url)

        return {
            "public": list(set(public)),
            "hidden": list(set(hidden)),
            "sensitive": list(set(sensitive))
        }
