from core.parameter_extractor import ParameterExtractor


class ParameterScanner:

    def __init__(self, keywords=None):

        self.extractor = ParameterExtractor()

        self.keywords = keywords or [
            "id", "user", "token", "auth",
            "key", "password", "email", "session"
        ]

    def scan(self, files_dict):

        params = self.extractor.extract_from_files(files_dict)

        params = list(set(params))

        interesting = []

        for p in params:

            for k in self.keywords:
                if k in p.lower():
                    interesting.append(p)
                    break

        return {
            "total": len(params),
            "interesting": list(set(interesting)),
            "all": params
        }