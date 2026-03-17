import time

from core.endpoint_extractor import EndpointExtractor
from core.classifier import EndpointClassifier
from core.validator import EndpointValidator

from utils.logger import Logger


class EndpointScanner:

    def __init__(self, validate=True, delay=0):

        self.extractor = EndpointExtractor()
        self.classifier = EndpointClassifier()
        self.validator = EndpointValidator()

        self.validate_enabled = validate
        self.delay = delay

    # =========================
    # MAIN SCAN FUNCTION
    # =========================
    def scan(self, data):

        """
        data bisa berupa:
        - dict files (OSINT)
        - list endpoints (manual / external)
        """

        # =========================
        # 1. EXTRACT / NORMALIZE
        # =========================
        if isinstance(data, dict):
            Logger.info("Extracting endpoints from files...")
            endpoints = self.extractor.extract_from_files(data)

        elif isinstance(data, list):
            Logger.info("Using provided endpoints list...")
            endpoints = data

        else:
            Logger.error("Invalid input for endpoint scanner")
            return {
                "total_found": 0,
                "total_valid": 0,
                "classified": {"public": [], "hidden": [], "sensitive": []}
            }

        # Deduplicate
        endpoints = list(set(endpoints))

        Logger.info(f"Extracted endpoints: {len(endpoints)}")

        if not endpoints:
            Logger.warn("No endpoints found")
            return {
                "total_found": 0,
                "total_valid": 0,
                "classified": {"public": [], "hidden": [], "sensitive": []}
            }

        # =========================
        # 2. VALIDATION (OPTIONAL)
        # =========================
        valid_endpoints = []

        if self.validate_enabled:

            Logger.info("Validating endpoints...")

            for ep in endpoints:

                status = self.validator.validate(ep)

                if status:
                    valid_endpoints.append(ep)
                    Logger.debug(f"[VALID] {ep}")

                if self.delay > 0:
                    time.sleep(self.delay)

        else:
            Logger.info("Validation disabled")
            valid_endpoints = endpoints

        Logger.success(f"Valid endpoints: {len(valid_endpoints)}")

        if not valid_endpoints:
            Logger.warn("No valid endpoints after validation")
            return {
                "total_found": len(endpoints),
                "total_valid": 0,
                "classified": {"public": [], "hidden": [], "sensitive": []}
            }

        # =========================
        # 3. CLASSIFICATION
        # =========================
        Logger.info("Classifying endpoints...")

        classified = self.classifier.classify_list(valid_endpoints)

        return {
            "total_found": len(endpoints),
            "total_valid": len(valid_endpoints),
            "classified": classified
        }

    # =========================
    # 🔥 OPTIONAL: STATUS-BASED MODE
    # =========================
    def scan_with_status(self, results):

        """
        results format:
        [
            {"url": "...", "status_code": 200},
            ...
        ]
        """

        if not isinstance(results, list):
            Logger.error("Invalid status-based input")
            return {
                "public": [],
                "hidden": [],
                "sensitive": []
            }

        Logger.info("Classifying based on HTTP status...")

        classified = self.classifier.classify_status(results)

        return classified
