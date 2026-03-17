class RepoCrawler:
    
    def extract_repos(self, search_results):

        repos = set()

        for item in search_results:
            repos.add(item["repo"])

        return list(repos)