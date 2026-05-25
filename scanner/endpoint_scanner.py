from core.endpoint_extractor import EndpointExtractor
from core.classifier import EndpointClassifier
from core.validator import EndpointValidator
from filters.endpoint_filter import EndpointFilter
from filters.domain_filter import DomainFilter
from utils.logger import Logger


class EndpointScanner:
    def __init__(self, target_domain: str = None, validate: bool = True, delay_range: tuple = (1, 2)):
        self.target_domain = target_domain
        self.validate_enabled = validate

        self.extractor = EndpointExtractor()
        self.classifier = EndpointClassifier()
        self.validator = EndpointValidator(delay_range=delay_range)
        self.ep_filter = EndpointFilter()
        self.domain_filter = DomainFilter(target_domain) if target_domain else None

    # =========================
    # 🚀 MAIN SCAN
    # =========================
    def scan(self, data) -> dict:
        """
        data bisa:
        - dict {filename: content}  → extract dari source code files
        - list [url, url, ...]      → langsung validate & classify
        """

        # ── STEP 1: EXTRACT ──
        endpoints = self._extract(data)
        if not endpoints:
            Logger.warn("No endpoints found after extraction")
            return self._empty_result()

        Logger.info(f"Extracted: {len(endpoints)} endpoints")

        # ── STEP 2: FILTER ──
        endpoints = self._apply_filters(endpoints)
        Logger.info(f"After filter: {len(endpoints)} endpoints")

        if not endpoints:
            Logger.warn("No endpoints after filtering")
            return self._empty_result()

        # ── STEP 3: VALIDATE ──
        if self.validate_enabled:
            Logger.info("Validating endpoints...")
            validated = self.validator.validate_multiple(endpoints)
        else:
            Logger.info("Validation disabled — skipping")
            # Buat mock result tanpa HTTP request
            validated = [{"url": ep, "status_code": None, "content": "", "fingerprint": ""} for ep in endpoints]

        Logger.success(f"Validated: {len(validated)} endpoints")

        if not validated:
            return self._empty_result(len(endpoints))

        # ── STEP 4: CLASSIFY ──
        Logger.info("Classifying endpoints...")
        classified = self.classifier.classify_status(validated)

        # ── STEP 5: DUPLICATE DETECTION ──
        Logger.info("Running duplicate detection...")
        dup_analysis = self.validator.detect_duplicates(validated)

        if dup_analysis["duplicate_groups"] or dup_analysis["similar_pairs"]:
            self.validator.print_duplicate_report(dup_analysis)

        # ── STEP 6: SCORING ──
        all_urls = [r["url"] for r in validated]
        scored = self.ep_filter.filter_and_score(all_urls)

        return {
            "total_found": len(endpoints),
            "total_validated": len(validated),
            "classified": classified,
            "duplicate_analysis": dup_analysis,
            "scored": scored[:20],  # top 20
            "raw": validated,
        }

    # =========================
    # 🔥 STATUS-BASED SCAN
    # =========================
    def scan_with_status(self, results: list) -> dict:
        """
        Input: list of {url, status_code, content, ...}
        Classify + duplicate detection dari hasil yang sudah ada.
        """
        if not isinstance(results, list):
            Logger.error("Invalid input: expected list")
            return {"public": [], "hidden": [], "sensitive": []}

        Logger.info(f"Classifying {len(results)} results by status...")
        classified = self.classifier.classify_status(results)

        Logger.info("Running duplicate detection...")
        dup_analysis = self.validator.detect_duplicates(results)

        if dup_analysis["duplicate_groups"] or dup_analysis["similar_pairs"]:
            self.validator.print_duplicate_report(dup_analysis)

        return {
            "classified": classified,
            "duplicate_analysis": dup_analysis,
        }

    # =========================
    # 🔍 OSINT-ONLY SCAN (tanpa HTTP request)
    # =========================
    def scan_osint(self, files_dict: dict) -> dict:
        """
        Hanya extract + classify berdasarkan keyword, tanpa hit target server.
        Berguna untuk reconnaissance awal.
        """
        Logger.info("OSINT-only scan (no HTTP requests)...")
        endpoints = self.extractor.extract_from_files(files_dict)
        endpoints = list(set(endpoints))

        if not endpoints:
            Logger.warn("No endpoints extracted")
            return self._empty_result()

        filtered = self.ep_filter.filter(endpoints)
        if self.domain_filter:
            filtered = self.domain_filter.filter_and_build(filtered)

        classified = self.classifier.classify_list(filtered)
        by_type = self.ep_filter.separate_by_type(filtered)
        scored = self.ep_filter.filter_and_score(filtered)

        Logger.success(f"OSINT found: {len(filtered)} endpoints")

        return {
            "total_found": len(endpoints),
            "total_after_filter": len(filtered),
            "classified": classified,
            "by_type": by_type,
            "scored": scored[:20],
            "duplicate_analysis": None,
            "raw": filtered,
        }

    # =========================
    # 🔧 INTERNAL HELPERS
    # =========================
    def _extract(self, data) -> list:
        if isinstance(data, dict):
            Logger.info("Extracting from source files...")
            if self.target_domain:
                return self.extractor.extract_and_build(data, self.target_domain)
            return self.extractor.extract_from_files(data)
        elif isinstance(data, list):
            Logger.info("Using provided endpoint list...")
            return list(set(data))
        else:
            Logger.error(f"Invalid input type: {type(data)}")
            return []

    def _apply_filters(self, endpoints: list) -> list:
        # Filter dasar (ekstensi, panjang, template)
        filtered = self.ep_filter.filter(endpoints)
        # Deduplikasi dengan normalisasi
        filtered = self.ep_filter.deduplicate(filtered)
        # Filter domain jika ada
        if self.domain_filter:
            filtered = self.domain_filter.filter(filtered)
        return filtered

    def _empty_result(self, total_found: int = 0) -> dict:
        return {
            "total_found": total_found,
            "total_validated": 0,
            "classified": {"public": [], "hidden": [], "sensitive": []},
            "duplicate_analysis": None,
            "scored": [],
            "raw": [],
        }
