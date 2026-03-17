import requests


class Downloader:

    def __init__(self, timeout=10):
        self.timeout = timeout

    def fetch(self, url):

        try:
            r = requests.get(url, timeout=self.timeout)

            if r.status_code == 200:
                return r.text

            return None

        except requests.RequestException:
            return None

    def fetch_multiple(self, items):

        results = {}

        for item in items:

            content = self.fetch(item["raw_url"])

            if content:
                results[item["raw_url"]] = content

        return results