class EndpointClassifier:
    
    def __init__(self, hidden_keywords=None, sensitive_keywords=None):

        self.hidden_keywords = hidden_keywords or [
            "admin", "internal", "private", "dashboard", "panel"
        ]

        self.sensitive_keywords = sensitive_keywords or [
            "login", "auth", "token", "apikey", "password"
        ]

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

        return results