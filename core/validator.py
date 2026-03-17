import requests


class EndpointValidator:

    def __init__(self, timeout=10):

        self.timeout = timeout

        self.blocked = [
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            ".local",
            "dev",
            "test"
        ]

    def is_valid(self, url):

        for b in self.blocked:
            if b in url:
                return False

        return True

    def validate(self, url):

        if not self.is_valid(url):
            return None

        try:

            r = requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=True
            )

            return r.status_code

        except requests.RequestException:
            return None

    def validate_multiple(self, urls):

        results = {}

        for url in urls:

            status = self.validate(url)

            if status:
                results[url] = status

        return results