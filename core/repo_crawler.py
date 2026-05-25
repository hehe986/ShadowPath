import requests
import time
import random


class RepoCrawler:
    def __init__(self, github_token=None):
        self.github_token = github_token
        self.delay_range = (1, 3)

    def _delay(self):
        time.sleep(random.uniform(*self.delay_range))

    def _github_headers(self):
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        return headers

    # =========================
    # 🔹 EXTRACT REPO LIST
    # =========================
    def extract_repos(self, search_results: list) -> list:
        """Extract unique repo names dari search results."""
        repos = set()
        for item in search_results:
            repo = item.get("repo")
            if repo:
                repos.add(repo)
        return list(repos)

    # =========================
    # 🔹 GET FILE LIST DARI REPO
    # =========================
    def get_repo_files(self, repo_full_name: str, source: str = "github",
                       extensions: list = None) -> list:
        """
        Ambil daftar file dari sebuah repo.
        repo_full_name: 'owner/repo'
        extensions: filter ekstensi, misal ['.py', '.js', '.ts']
        """
        if extensions is None:
            extensions = [
                ".py", ".js", ".ts", ".go", ".java", ".php",
                ".rb", ".cs", ".env", ".yaml", ".yml", ".json",
                ".xml", ".conf", ".config", ".toml", ".ini"
            ]

        if source == "github":
            return self._get_github_files(repo_full_name, extensions)
        elif source == "gitlab":
            return self._get_gitlab_files(repo_full_name, extensions)
        return []

    def _get_github_files(self, repo_full_name: str, extensions: list) -> list:
        url = f"https://api.github.com/repos/{repo_full_name}/git/trees/HEAD"
        params = {"recursive": "1"}

        try:
            self._delay()
            r = requests.get(
                url,
                headers=self._github_headers(),
                params=params,
                timeout=10
            )
            if r.status_code != 200:
                return []

            files = []
            for item in r.json().get("tree", []):
                if item.get("type") != "blob":
                    continue
                path = item.get("path", "")
                if any(path.endswith(ext) for ext in extensions):
                    raw_url = f"https://raw.githubusercontent.com/{repo_full_name}/HEAD/{path}"
                    files.append({
                        "source": "github",
                        "repo": repo_full_name,
                        "file_path": path,
                        "file_name": path.split("/")[-1],
                        "raw_url": raw_url,
                        "file_url": f"https://github.com/{repo_full_name}/blob/HEAD/{path}",
                    })
            return files

        except requests.RequestException as e:
            print(f"[RepoCrawler][GitHub] Error: {e}")
            return []

    def _get_gitlab_files(self, project_id: str, extensions: list) -> list:
        url = f"https://gitlab.com/api/v4/projects/{project_id}/repository/tree"
        params = {"recursive": True, "per_page": 100}

        try:
            self._delay()
            r = requests.get(url, params=params, timeout=10)
            if r.status_code != 200:
                return []

            files = []
            for item in r.json():
                if item.get("type") != "blob":
                    continue
                path = item.get("path", "")
                if any(path.endswith(ext) for ext in extensions):
                    raw_url = f"https://gitlab.com/api/v4/projects/{project_id}/repository/files/{requests.utils.quote(path, safe='')}/raw"
                    files.append({
                        "source": "gitlab",
                        "repo": project_id,
                        "file_path": path,
                        "file_name": path.split("/")[-1],
                        "raw_url": raw_url,
                        "file_url": raw_url,
                    })
            return files

        except requests.RequestException as e:
            print(f"[RepoCrawler][GitLab] Error: {e}")
            return []

    # =========================
    # 🔹 CRAWL MULTIPLE REPOS
    # =========================
    def crawl_repos(self, search_results: list, extensions: list = None) -> list:
        """
        Crawl semua repo dari search results untuk mendapatkan file list.
        Returns: flat list of file items
        """
        all_files = []
        seen_repos = set()

        for item in search_results:
            repo = item.get("repo")
            source = item.get("source", "github")
            if not repo or repo in seen_repos:
                continue
            seen_repos.add(repo)

            print(f"[RepoCrawler] Crawling {source}/{repo}...")
            files = self.get_repo_files(repo, source=source, extensions=extensions)
            all_files.extend(files)

        print(f"[RepoCrawler] Total file ditemukan: {len(all_files)}")
        return all_files
