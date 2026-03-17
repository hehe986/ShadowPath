from urllib.parse import urlparse


class DomainFilter:

    def __init__(self, target_domain):
        self.target = target_domain.lower()

    def is_valid(self, url):

        try:
            parsed = urlparse(url)

            if not parsed.netloc:
                return False

            return self.target in parsed.netloc.lower()

        except Exception:
            return False

    def filter(self, endpoints):

        results = []

        for ep in endpoints:

            if self.is_valid(ep):
                results.append(ep)

        return list(set(results))