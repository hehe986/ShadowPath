import time
from core.endpoint_extractor import EndpointExtractor
from core.classifier import EndpointClassifier
from core.validator import EndpointValidator


class EndpointScanner:

    def __init__(self, validate=True, delay=0):

        self.extractor = EndpointExtractor()
        self.classifier = EndpointClassifier()
        self.validator = EndpointValidator()

        self.validate_enabled = validate
        self.delay = delay

    def scan(self, files_dict):

        # 1. Extract endpoints
        endpoints = self.extractor.extract_from_files(files_dict)

        # Deduplicate
        endpoints = list(set(endpoints))

        # 2. Validate (optional)
        valid_endpoints = []

        if self.validate_enabled:

            for ep in endpoints:

                status = self.validator.validate(ep)

                if status:
                    valid_endpoints.append(ep)

                if self.delay > 0:
                    time.sleep(self.delay)

        else:
            valid_endpoints = endpoints

        # 3. Classify
        classified = self.classifier.classify_list(valid_endpoints)

        return {
            "total_found": len(endpoints),
            "total_valid": len(valid_endpoints),
            "classified": classified
        }