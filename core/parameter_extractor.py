import re


class ParameterExtractor:

    def __init__(self):

        self.patterns = [
            r'[?&]([a-zA-Z0-9_\-]+)=',
            r'([a-zA-Z0-9_\-]+)\s*='
        ]

    def extract_from_text(self, text):

        params = set()

        for pattern in self.patterns:

            matches = re.findall(pattern, text)

            for match in matches:

                if len(match) < 30:
                    params.add(match)

        return list(params)

    def extract_from_files(self, files_dict):

        results = []

        for _, content in files_dict.items():

            results.extend(self.extract_from_text(content))

        return list(set(results))