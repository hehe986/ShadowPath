import requests


class GitHubSearch:

    def __init__(self, token=None):
        self.base_url = "https://api.github.com/search/code"
        self.token = token

    def search_code(self, query, per_page=10):

        headers = {}

        if self.token:
            headers["Authorization"] = f"token {self.token}"

        params = {
            "q": query,
            "per_page": per_page
        }

        try:
            r = requests.get(self.base_url, headers=headers, params=params)

            if r.status_code != 200:
                return []

            data = r.json()

            results = []

            for item in data.get("items", []):
                results.append({
                    "repo": item["repository"]["full_name"],
                    "file_url": item["html_url"],
                    "raw_url": item["html_url"]
                        .replace("github.com", "raw.githubusercontent.com")
                        .replace("/blob/", "/")
                })

            return results

        except requests.RequestException:
            return []