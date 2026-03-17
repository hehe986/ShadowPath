class EndpointFilter:
    
    def __init__(self):

        self.blacklist_ext = [
            ".jpg", ".jpeg", ".png", ".gif",
            ".css", ".svg", ".woff", ".ttf",
            ".ico", ".mp4", ".mp3"
        ]

        self.min_length = 3

    def is_valid(self, endpoint):

        ep = endpoint.lower()

        # terlalu pendek
        if len(ep) < self.min_length:
            return False

        # file statis
        for ext in self.blacklist_ext:
            if ep.endswith(ext):
                return False

        return True

    def filter(self, endpoints):

        results = []

        for ep in endpoints:

            if self.is_valid(ep):
                results.append(ep)

        return list(set(results))