"""
scanner/crawl_scanner.py — Real-Time Crawl Scanner
====================================================
Mode baru yang spider langsung ke target (bukan dari GitHub),
extract endpoint dari HTML/JS yang ditemukan secara live,
lalu classify + validate + extract parameter.

Pipeline:
  WebCrawler → raw pages
      ↓
  EndpointExtractor (dari konten HTML/JS yang di-crawl)
      ↓
  EndpointFilter + DomainFilter
      ↓
  EndpointClassifier (keyword + status code)
      ↓
  ParameterExtractor (dari source code yang ditemukan)
      ↓
  Output
"""

from core.web_crawler import WebCrawler
from core.endpoint_extractor import EndpointExtractor
from core.parameter_extractor import ParameterExtractor
from core.classifier import EndpointClassifier
from core.validator import EndpointValidator
from core.live_checker import LiveChecker, STATUS_LIVE, STATUS_REACHABLE_EMPTY
from filters.endpoint_filter import EndpointFilter
from filters.domain_filter import DomainFilter
from utils.logger import Logger


class CrawlScanner:

    def __init__(self,
                 target_domain: str,
                 max_pages: int = 100,
                 max_depth: int = 4,
                 timing_mode: str = "normal",
                 validate: bool = True,
                 crawl_js: bool = True,
                 follow_subdomains: bool = False,
                 timeout: int = 10,
                 verify_liveness: bool = True):

        self.target           = target_domain
        self.validate_enabled = validate
        self.verify_liveness  = verify_liveness
        self.follow_subdomains = follow_subdomains

        self.crawler    = WebCrawler(
            target_domain=target_domain,
            max_pages=max_pages,
            max_depth=max_depth,
            timing_mode=timing_mode,
            crawl_js=crawl_js,
            follow_subdomains=follow_subdomains,
            timeout=timeout,
        )
        self.extractor      = EndpointExtractor()
        self.param_extractor = ParameterExtractor()
        self.classifier     = EndpointClassifier()
        self.validator      = EndpointValidator(timeout=timeout)
        self.ep_filter      = EndpointFilter()
        self.domain_filter  = DomainFilter(target_domain,
                                           include_subdomains=follow_subdomains)
        self.live_checker   = LiveChecker(timeout=timeout, threads=5)

    # =============================================================
    # 🚀 MAIN SCAN
    # =============================================================
    def scan(self, seed_url: str = None) -> dict:
        """
        Jalankan crawl scan lengkap.

        Returns dict:
          classified, parameters, duplicate_analysis, scored,
          crawl_stats, urls, forms, raw, live_hosts
        """
        Logger.section("CRAWL MODE — Real-Time Web Spider")

        # ── STEP 0: PRE-FLIGHT LIVENESS CHECK ────────────────
        Logger.info("Phase 0: Verifying target liveness...")
        target_check = self.live_checker.check_host(self.target)

        if target_check["status"] not in (STATUS_LIVE, STATUS_REACHABLE_EMPTY):
            Logger.error(
                f"Target {self.target} tidak accessible "
                f"(status: {target_check['status']}, reason: {target_check['reason']})"
            )
            Logger.warn("Scan dibatalkan — target tidak hidup.")
            result = self._empty_result()
            result["live_hosts"] = {"verified": [target_check]}
            return result

        Logger.success(
            f"Target LIVE: {self.target} "
            f"(status:{target_check.get('http_status') or target_check.get('https_status')}, "
            f"len:{target_check['content_length']}, "
            f"server:{target_check.get('server', '?')})"
        )
        if target_check["title"]:
            Logger.info(f"  Title: {target_check['title']}")
        print()

        # ── STEP 1: CRAWL ──────────────────────────────────────
        Logger.info("Phase 1: Crawling target...")
        crawl_result = self.crawler.crawl(seed_url)
        crawl_stats  = crawl_result["stats"]

        Logger.success(
            f"Crawl done — {crawl_stats['pages_crawled']} pages, "
            f"{crawl_stats['urls_found']} URLs, "
            f"{crawl_stats['js_files']} JS files"
        )

        raw_pages = crawl_result.get("raw_pages", {})
        if not raw_pages:
            Logger.warn("No page content retrieved — target mungkin tidak accessible")
            return self._empty_result()

        # ── STEP 2: EXTRACT ENDPOINTS ──────────────────────────
        Logger.info("Phase 2: Extracting endpoints from crawled content...")

        # Dari raw page content (HTML + JS)
        eps_from_content = self.extractor.extract_from_files(raw_pages)

        # Dari URL yang ditemukan crawler (link navigation)
        eps_from_urls = list(crawl_result.get("urls", []))

        # Dari endpoint yang sudah di-detect crawler saat parsing JS
        eps_from_js   = list(crawl_result.get("endpoints", []))

        # Gabung semua sumber
        all_eps = list(set(eps_from_content + eps_from_urls + eps_from_js))
        Logger.info(f"Raw endpoints: {len(all_eps)} (content:{len(eps_from_content)}, "
                    f"nav:{len(eps_from_urls)}, js:{len(eps_from_js)})")

        # ── STEP 3: FILTER ─────────────────────────────────────
        Logger.info("Phase 3: Filtering endpoints...")
        filtered = self.ep_filter.filter(all_eps)
        filtered = self.ep_filter.deduplicate(filtered)
        filtered = self.domain_filter.filter_and_build(filtered)
        Logger.info(f"After filter: {len(filtered)} endpoints")

        if not filtered:
            Logger.warn("No endpoints after filtering")
            return self._empty_result()

        # ── STEP 3.5: HOST LIVENESS VERIFICATION ───────────────
        # Extract unique hosts dari filtered endpoints, verifikasi setiap host aktif.
        # Endpoint yang host-nya tidak live akan di-drop supaya hasil tidak "halu".
        live_check_data = self._verify_endpoint_hosts(filtered)
        filtered = live_check_data["endpoints_on_live_hosts"]
        Logger.info(f"After liveness filter: {len(filtered)} endpoints on {live_check_data['live_count']} live hosts")

        if not filtered:
            Logger.warn("Tidak ada endpoint pada host yang benar-benar hidup")
            return self._empty_result()

        # ── STEP 4: VALIDATE ───────────────────────────────────
        if self.validate_enabled:
            Logger.info("Phase 4: Validating endpoints (HTTP requests)...")
            validated = self.validator.validate_multiple(filtered)
            Logger.success(f"Validated: {len(validated)} live endpoints")
        else:
            Logger.info("Phase 4: Validation disabled — using extracted only")
            validated = [
                {"url": ep, "status_code": None, "content": "", "fingerprint": ""}
                for ep in filtered
            ]

        if not validated:
            return self._empty_result()

        # ── STEP 5: CLASSIFY (4-WAY) ───────────────────────────
        Logger.info("Phase 5: Classifying endpoints (4-way: public/private × open/closed)...")
        if self.validate_enabled:
            classified = self.classifier.classify_status(validated)
        else:
            urls_only  = [v["url"] for v in validated]
            # Tanpa validasi, tidak bisa tahu open/closed. Fallback ke legacy.
            classified = self.classifier.classify_list(urls_only)

        # ── STEP 6: DUPLICATE DETECTION ────────────────────────
        Logger.info("Phase 6: Duplicate response detection...")
        if self.validate_enabled:
            dup_analysis = self.validator.detect_duplicates(validated)
        else:
            dup_analysis = None

        # ── STEP 7: SCORING ────────────────────────────────────
        scored = self.ep_filter.filter_and_score(
            [v["url"] for v in validated]
        )

        # ── STEP 8: PARAMETER EXTRACTION ───────────────────────
        Logger.info("Phase 7: Extracting parameters from crawled content...")
        param_data = self._extract_params(raw_pages, validated, crawl_result)

        # ── STEP 9: FORM ANALYSIS ──────────────────────────────
        forms = crawl_result.get("forms", [])
        if forms:
            Logger.info(f"Found {len(forms)} forms — extracting params...")
            for form in forms:
                Logger.info(f"  [{form.get('method','GET')}] {form.get('action','')}")

        # ── PRINT INLINE RESULTS ───────────────────────────────
        self._print_inline(classified, dup_analysis, scored, param_data,
                           live_check_data)

        return {
            "mode":             "crawl",
            "target_check":     target_check,
            "live_hosts":       live_check_data,
            "classified":       classified,
            "duplicate_analysis": dup_analysis,
            "scored":           scored[:20],
            "parameters":       param_data,
            "forms":            forms,
            "urls":             list(crawl_result.get("urls", [])),
            "crawl_stats":      crawl_stats,
            "raw":              validated,
            "total_found":      len(all_eps),
            "total_after_filter": len(filtered),
            "total_validated":  len(validated),
        }

    # =============================================================
    # 🔍 HOST LIVENESS VERIFICATION
    # =============================================================
    def _verify_endpoint_hosts(self, endpoints: list) -> dict:
        """
        Extract unique host dari list endpoint, verifikasi setiap host
        benar-benar hidup, filter endpoint yang host-nya mati.

        Returns:
          endpoints_on_live_hosts: list URL yang host-nya verified LIVE/EMPTY
          live_count: jumlah host live
          host_results: full result dari LiveChecker per host
          verified_grouped: dict {status → [host_result]}
        """
        from urllib.parse import urlparse

        # Extract unique hosts
        hosts = set()
        for ep in endpoints:
            try:
                p = urlparse(ep)
                if p.netloc:
                    hosts.add(p.netloc.split(":")[0].lower())
            except Exception:
                pass

        if not hosts:
            return {
                "endpoints_on_live_hosts": endpoints,
                "live_count": 0,
                "host_results": [],
                "verified_grouped": {},
            }

        Logger.info(f"Verifying {len(hosts)} unique hosts before endpoint scan...")
        host_results = self.live_checker.check_multiple(list(hosts))
        grouped      = self.live_checker.group_by_status(host_results)

        # Host yang LIVE atau REACHABLE_EMPTY tetap boleh discan
        # (REACHABLE_EMPTY masih ada HTTP server yang respond)
        accessible_hosts = {
            r["host"] for r in host_results
            if r["status"] in (STATUS_LIVE, STATUS_REACHABLE_EMPTY)
        }

        # Filter endpoint
        filtered_eps = []
        for ep in endpoints:
            try:
                host = urlparse(ep).netloc.split(":")[0].lower()
                if host in accessible_hosts:
                    filtered_eps.append(ep)
            except Exception:
                pass

        return {
            "endpoints_on_live_hosts": filtered_eps,
            "live_count":              len(grouped[STATUS_LIVE]),
            "empty_count":             len(grouped[STATUS_REACHABLE_EMPTY]),
            "dns_only_count":          len(grouped["dns_only"]),
            "dead_count":              len(grouped["dead"]),
            "host_results":            host_results,
            "verified_grouped":        grouped,
        }

    # =============================================================
    # 🔑 PARAMETER EXTRACTION
    # =============================================================
    def _extract_params(self, raw_pages: dict, validated: list,
                        crawl_result: dict) -> dict:
        """Extract parameter dari semua sumber yang tersedia."""

        # Dari source code halaman (raw HTML/JS)
        all_params = set(self.param_extractor.extract_from_files(raw_pages))

        # Dari query string URL yang ditemukan
        from urllib.parse import urlparse, parse_qs
        for item in validated:
            url = item.get("url", "")
            try:
                parsed = urlparse(url)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    all_params.update(params.keys())
            except Exception:
                pass

        all_params = list(all_params)
        sensitive  = [
            p for p in all_params
            if any(s in p.lower() for s in self.param_extractor.sensitive_params)
        ]

        cats = self._categorize_params(all_params)
        qs   = self.param_extractor.build_query_string(sensitive or all_params[:10])

        return {
            "total":                  len(all_params),
            "sensitive":              sensitive,
            "by_category":            cats,
            "query_string_template":  qs,
            "all":                    all_params,
        }

    def _categorize_params(self, params: list) -> dict:
        cats = {"auth": [], "id": [], "file": [], "debug": [], "general": []}
        auth_kw  = {"token","auth","password","passwd","pwd","secret","key",
                    "api_key","apikey","session","jwt","bearer","oauth","credential","refresh","access"}
        id_kw    = {"id","uid","uuid","user","username","email","account","member","profile"}
        file_kw  = {"file","path","dir","folder","upload","download","attachment","filename","filepath"}
        debug_kw = {"debug","test","dev","verbose","trace","log","mock","sandbox"}
        for p in params:
            pl = p.lower()
            if any(k in pl for k in auth_kw):    cats["auth"].append(p)
            elif any(k in pl for k in id_kw):    cats["id"].append(p)
            elif any(k in pl for k in file_kw):  cats["file"].append(p)
            elif any(k in pl for k in debug_kw): cats["debug"].append(p)
            else:                                 cats["general"].append(p)
        return cats

    # =============================================================
    # 🖨️ INLINE PRINT
    # =============================================================
    def _print_inline(self, classified: dict, dup_analysis,
                      scored: list, param_data: dict,
                      live_check_data: dict = None):
        from utils.output import OutputFormatter

        # Liveness summary dulu
        if live_check_data:
            Logger.section("HOST LIVENESS SUMMARY")
            print(f"  🟢 LIVE            : {live_check_data.get('live_count', 0)} hosts (aplikasi aktif)")
            print(f"  ⚪ REACHABLE_EMPTY : {live_check_data.get('empty_count', 0)} hosts (respond, tapi parking/kosong)")
            print(f"  🟡 DNS_ONLY        : {live_check_data.get('dns_only_count', 0)} hosts (DNS resolve, HTTP mati)")
            print(f"  🔴 DEAD            : {live_check_data.get('dead_count', 0)} hosts (tidak resolve)")
            print()

            live_hosts = [r for r in live_check_data.get("host_results", [])
                          if r["status"] == "live"]
            if live_hosts:
                print("  Host LIVE (verified):")
                for h in sorted(live_hosts, key=lambda x: x["host"]):
                    title = f" — {h['title']}" if h.get('title') else ""
                    print(f"    • {h['host']:<40} [{h.get('server','?')}]{title}")
                print()

        OutputFormatter.print_results(classified)

        if dup_analysis:
            s = dup_analysis.get("summary", {})
            if s.get("exact_duplicates") or s.get("similar_pairs"):
                OutputFormatter.print_duplicate_report(dup_analysis)

        if param_data.get("total"):
            OutputFormatter.print_parameters(param_data)

        if scored:
            OutputFormatter.print_scored(scored, top=10)

    # =============================================================
    # 📊 HELPERS
    # =============================================================
    def _empty_result(self) -> dict:
        return {
            "mode": "crawl",
            "target_check": None,
            "live_hosts": {},
            "classified": {
                "public_open": [], "public_closed": [],
                "private_open": [], "private_closed": [],
                "public": [], "hidden": [], "sensitive": [],
            },
            "duplicate_analysis": None,
            "scored": [],
            "parameters": {"total": 0, "sensitive": [], "all": [],
                           "by_category": {}, "query_string_template": ""},
            "forms": [],
            "urls": [],
            "crawl_stats": {},
            "raw": [],
            "total_found": 0,
            "total_after_filter": 0,
            "total_validated": 0,
        }

    def close(self):
        self.crawler.close()
        self.live_checker.close()
