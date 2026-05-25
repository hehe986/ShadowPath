import requests
import time
import random


class GitHubSearch:
    def __init__(self, token=None, gitlab_token=None, bitbucket_user=None, bitbucket_app_password=None):
        self.token = token
        self.gitlab_token = gitlab_token
        self.bitbucket_auth = (
            (bitbucket_user, bitbucket_app_password)
            if bitbucket_user and bitbucket_app_password else None
        )
        self.delay_range = (2, 4)

    def _delay(self):
        time.sleep(random.uniform(*self.delay_range))

    # =========================
    # 🐙 GITHUB SEARCH
    # =========================
    def search_code(self, query: str, per_page: int = 10) -> list:
        url = "https://api.github.com/search/code"
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.token:
            headers["Authorization"] = f"token {self.token}"

        params = {"q": query, "per_page": min(per_page, 100)}

        try:
            self._delay()
            r = requests.get(url, headers=headers, params=params, timeout=10)

            if r.status_code == 403:
                retry_after = int(r.headers.get("Retry-After", 60))
                print(f"[GitHub] Rate limited. Tunggu {retry_after}s...")
                time.sleep(retry_after)
                return []

            if r.status_code != 200:
                print(f"[GitHub] Error {r.status_code}: {r.text[:100]}")
                return []

            results = []
            for item in r.json().get("items", []):
                html_url = item["html_url"]
                raw_url = (
                    html_url
                    .replace("github.com", "raw.githubusercontent.com")
                    .replace("/blob/", "/")
                )
                results.append({
                    "source": "github",
                    "repo": item["repository"]["full_name"],
                    "file_url": html_url,
                    "raw_url": raw_url,
                    "file_name": item.get("name", ""),
                    "file_path": item.get("path", ""),
                })
            return results

        except requests.RequestException as e:
            print(f"[GitHub] Request error: {e}")
            return []

    # =========================
    # 🦊 GITLAB SEARCH
    # =========================
    def search_gitlab(self, query: str, per_page: int = 10) -> list:
        url = "https://gitlab.com/api/v4/search"
        headers = {}
        if self.gitlab_token:
            headers["PRIVATE-TOKEN"] = self.gitlab_token

        params = {
            "scope": "blobs",
            "search": query,
            "per_page": min(per_page, 100),
        }

        try:
            self._delay()
            r = requests.get(url, headers=headers, params=params, timeout=10)

            if r.status_code == 429:
                print("[GitLab] Rate limited. Tunggu 60s...")
                time.sleep(60)
                return []

            if r.status_code != 200:
                print(f"[GitLab] Error {r.status_code}: {r.text[:100]}")
                return []

            results = []
            for item in r.json():
                project_id = item.get("project_id")
                file_path = item.get("filename", "")
                ref = item.get("ref", "main")

                file_url = f"https://gitlab.com/api/v4/projects/{project_id}/repository/files/{requests.utils.quote(file_path, safe='')}/raw?ref={ref}"
                results.append({
                    "source": "gitlab",
                    "repo": str(project_id),
                    "file_url": file_url,
                    "raw_url": file_url,
                    "file_name": file_path.split("/")[-1],
                    "file_path": file_path,
                })
            return results

        except requests.RequestException as e:
            print(f"[GitLab] Request error: {e}")
            return []

    # =========================
    # 🪣 BITBUCKET SEARCH
    # =========================
    def search_bitbucket(self, query: str, workspace: str = None) -> list:
        """
        Bitbucket tidak punya global code search di public API.
        Ini search di workspace spesifik jika diberikan.
        """
        if not workspace:
            print("[Bitbucket] Workspace diperlukan untuk search.")
            return []

        url = f"https://api.bitbucket.org/2.0/repositories/{workspace}"
        try:
            self._delay()
            r = requests.get(
                url,
                auth=self.bitbucket_auth,
                timeout=10,
                params={"q": f'name~"{query}"', "pagelen": 10}
            )

            if r.status_code != 200:
                print(f"[Bitbucket] Error {r.status_code}")
                return []

            results = []
            for repo in r.json().get("values", []):
                slug = repo.get("slug", "")
                full_name = repo.get("full_name", "")
                results.append({
                    "source": "bitbucket",
                    "repo": full_name,
                    "file_url": f"https://bitbucket.org/{full_name}",
                    "raw_url": f"https://api.bitbucket.org/2.0/repositories/{full_name}/src",
                    "file_name": slug,
                    "file_path": "",
                })
            return results

        except requests.RequestException as e:
            print(f"[Bitbucket] Request error: {e}")
            return []

    # =========================
    # 🔍 UNIFIED SEARCH (SEMUA SUMBER)
    # =========================
    def search_all(self, query: str, per_page: int = 10,
                   sources: list = None, bitbucket_workspace: str = None) -> list:
        """
        Cari dari semua sumber sekaligus.
        sources: ['github', 'gitlab', 'bitbucket'] atau None (semua)
        """
        if sources is None:
            sources = ["github", "gitlab", "bitbucket"]

        all_results = []

        if "github" in sources:
            print(f"[*] Searching GitHub: {query}")
            all_results.extend(self.search_code(query, per_page))

        if "gitlab" in sources:
            print(f"[*] Searching GitLab: {query}")
            all_results.extend(self.search_gitlab(query, per_page))

        if "bitbucket" in sources and bitbucket_workspace:
            print(f"[*] Searching Bitbucket: {query}")
            all_results.extend(self.search_bitbucket(query, bitbucket_workspace))

        # Deduplikasi berdasarkan raw_url
        seen = set()
        unique = []
        for item in all_results:
            key = item.get("raw_url", "")
            if key and key not in seen:
                seen.add(key)
                unique.append(item)

        print(f"[*] Total ditemukan: {len(unique)} file dari {len(all_results)} hasil")
        return unique

    # =========================
    # 🎯 BUILD QUERY DARI DOMAIN
    # =========================
    def build_queries(self, domain: str) -> list:
        """Generate berbagai query untuk satu domain target."""
        d = domain.replace("https://", "").replace("http://", "").rstrip("/")
        return [
            f'"{d}"',
            f'"{d}" api',
            f'"{d}" endpoint',
            f'"{d}" url',
            f'"{d}" baseurl',
            f'"{d}" base_url',
        ]
