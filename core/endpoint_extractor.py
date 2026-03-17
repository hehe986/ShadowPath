import re


class EndpointExtractor:

    def __init__(self):

        self.patterns = [
            r'["\'](/[^"\']+)["\']',
            r'["\'](https?://[^"\']+)["\']'
        ]

    def extract_from_text(self, text):

        endpoints = set()

        for pattern in self.patterns:

            matches = re.findall(pattern, text)

            for match in matches:

                if len(match) < 200:
                    endpoints.add(match)

        return list(endpoints)

    def extract_from_files(self, files_dict):

        results = []

        for _, content in files_dict.items():

            endpoints.extend(self.extract_from_text(content))

        return list(set(results))