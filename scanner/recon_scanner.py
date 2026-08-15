"""
scanner/recon_scanner.py - Full Reconnaissance Pipeline
========================================================
Gabungkan SubdomainFinder + CrawlScanner + Classifier 4-way
jadi satu workflow recon lengkap:

  1. Enumerate subdomain (crt.sh + OTX + HackerTarget + Wayback + bruteforce + permutation)
  2. Verify liveness (DNS + HTTP) - drop yang dead
  3. Crawl per subdomain yang LIVE atau REACHABLE_EMPTY
  4. Extract + classify endpoint 4-way per subdomain
  5. Aggregate hasil: subdomain map + endpoint map + kategori

Output berupa struktur:
  {
    "target": "target.com",
    "subdomain_stats": {...},
    "subdomains": {
      "api.target.com": {
        "status": "live",
        "endpoints": {"private_open": [...], "public_open": [...], ...},
        "parameters": [...],
      },
      ...
    },
    "aggregated": {
      "total_live_subs": N,
      "total_endpoints": N,
      "all_private_open": [...],  # dari semua subdomain
      ...
    }
  }
"""

from core.subdomain_finder import SubdomainFinder
from core.live_checker import STATUS_LIVE, STATUS_REACHABLE_EMPTY
from scanner.crawl_scanner import CrawlScanner
from utils.logger import Logger


class ReconScanner:

    def __init__(self,
                 target_domain: str,
                 max_subs: int = 500,
                 max_pages_per_sub: int = 20,
                 max_depth: int = 3,
                 timing_mode: str = "normal",
                 crawl_each: bool = True,
                 bruteforce: bool = True,
                 permutation: bool = True,
                 threads: int = 20,
                 skip_empty: bool = False):
        """
        Args:
            target_domain: root domain (misal "target.com")
            max_subs: batas maks subdomain enum
            max_pages_per_sub: batas halaman crawl per subdomain
            max_depth: kedalaman crawl per subdomain
            timing_mode: stealth timing
            crawl_each: kalau False, cuma enum subdomain tanpa crawl endpoint
            bruteforce: enable DNS bruteforce
            permutation: enable permutation
            threads: paralel worker untuk enum
            skip_empty: skip crawl subdomain yang REACHABLE_EMPTY (cuma yang LIVE)
        """
        self.target             = target_domain
        self.max_pages_per_sub  = max_pages_per_sub
        self.max_depth          = max_depth
        self.timing_mode        = timing_mode
        self.crawl_each         = crawl_each
        self.skip_empty         = skip_empty

        self.finder = SubdomainFinder(
            target_domain=target_domain,
            max_subs=max_subs,
            bruteforce=bruteforce,
            permutation=permutation,
            verify_liveness=True,
            timing_mode="fast",
            threads=threads,
        )

    # =============================================================
    # MAIN SCAN
    # =============================================================
    def scan(self) -> dict:
        Logger.section(f"RECON MODE - {self.target}")

        # ===== PHASE A: SUBDOMAIN ENUMERATION =====
        enum_result = self.finder.enumerate()

        live_hosts = enum_result["live_subdomains"]
        if not live_hosts:
            Logger.warn("No live subdomains found - recon complete")
            return {
                "target":     self.target,
                "mode":       "recon",
                "enum":       enum_result,
                "subdomains": {},
                "aggregated": self._empty_aggregated(),
            }

        # ===== PHASE B: FILTER HOST YANG AKAN DI-CRAWL =====
        # LIVE selalu di-crawl. REACHABLE_EMPTY di-crawl kecuali skip_empty=True.
        crawlable = []
        for detail in enum_result["live_details"]:
            if detail["status"] == STATUS_LIVE:
                crawlable.append(detail["host"])
            elif detail["status"] == STATUS_REACHABLE_EMPTY and not self.skip_empty:
                crawlable.append(detail["host"])

        Logger.section(f"CRAWL PER SUBDOMAIN ({len(crawlable)} targets)")

        if not self.crawl_each:
            Logger.info("crawl_each=False - skipping per-subdomain crawl")
            return {
                "target":     self.target,
                "mode":       "recon",
                "enum":       enum_result,
                "subdomains": {},
                "aggregated": self._aggregate({}, enum_result),
            }

        # ===== PHASE C: CRAWL PER SUBDOMAIN =====
        per_sub_results = {}
        for i, host in enumerate(crawlable, start=1):
            Logger.section(f"[{i}/{len(crawlable)}] Crawling: {host}")
            try:
                scanner = CrawlScanner(
                    target_domain=host,
                    max_pages=self.max_pages_per_sub,
                    max_depth=self.max_depth,
                    timing_mode=self.timing_mode,
                    validate=True,
                    crawl_js=True,
                    follow_subdomains=False,   # sudah handle di level recon
                    timeout=10,
                    verify_liveness=False,      # sudah diverifikasi di phase A
                )
                sub_result = scanner.scan()
                per_sub_results[host] = self._extract_summary(sub_result)
            except Exception as e:
                Logger.error(f"Error crawling {host}: {e}")
                per_sub_results[host] = {
                    "error": str(e),
                    "endpoints": self._empty_endpoints(),
                    "parameters": [],
                    "forms": [],
                }
            finally:
                try:
                    scanner.close()
                except Exception:
                    pass

        # ===== PHASE D: AGGREGATE =====
        aggregated = self._aggregate(per_sub_results, enum_result)

        # ===== PHASE E: PRINT SUMMARY =====
        self._print_summary(enum_result, per_sub_results, aggregated)

        return {
            "target":     self.target,
            "mode":       "recon",
            "enum":       enum_result,
            "subdomains": per_sub_results,
            "aggregated": aggregated,
        }

    # =============================================================
    # HELPERS
    # =============================================================
    def _extract_summary(self, crawl_result: dict) -> dict:
        """Extract data yang relevant dari crawl result."""
        classified = crawl_result.get("classified", {})
        return {
            "status":            "crawled",
            "endpoints": {
                "private_open":   classified.get("private_open", []),
                "public_open":    classified.get("public_open", []),
                "private_closed": classified.get("private_closed", []),
                "public_closed":  classified.get("public_closed", []),
            },
            "endpoint_count": (
                len(classified.get("private_open", [])) +
                len(classified.get("public_open", [])) +
                len(classified.get("private_closed", [])) +
                len(classified.get("public_closed", []))
            ),
            "parameters":     crawl_result.get("parameters", {}).get("all", []),
            "sensitive_params": crawl_result.get("parameters", {}).get("sensitive", []),
            "forms":          crawl_result.get("forms", []),
            "crawl_stats":    crawl_result.get("crawl_stats", {}),
        }

    def _empty_endpoints(self) -> dict:
        return {
            "private_open":   [],
            "public_open":    [],
            "private_closed": [],
            "public_closed":  [],
        }

    def _empty_aggregated(self) -> dict:
        return {
            "total_live_subs":       0,
            "total_crawled_subs":    0,
            "total_endpoints":       0,
            "all_private_open":      [],
            "all_public_open":       [],
            "all_private_closed":    [],
            "all_public_closed":     [],
            "all_parameters":        [],
            "all_sensitive_params":  [],
        }

    def _aggregate(self, per_sub: dict, enum_result: dict) -> dict:
        """Gabung hasil semua subdomain jadi 1 map global."""
        agg = self._empty_aggregated()
        agg["total_live_subs"]    = enum_result["stats"]["live_count"] + enum_result["stats"]["reachable_empty"]
        agg["total_crawled_subs"] = len(per_sub)

        all_priv_open   = set()
        all_pub_open    = set()
        all_priv_closed = set()
        all_pub_closed  = set()
        all_params      = set()
        all_sens_params = set()

        for host, data in per_sub.items():
            eps = data.get("endpoints", {})
            all_priv_open.update(eps.get("private_open", []))
            all_pub_open.update(eps.get("public_open", []))
            all_priv_closed.update(eps.get("private_closed", []))
            all_pub_closed.update(eps.get("public_closed", []))
            all_params.update(data.get("parameters", []))
            all_sens_params.update(data.get("sensitive_params", []))

        agg["all_private_open"]     = sorted(all_priv_open)
        agg["all_public_open"]      = sorted(all_pub_open)
        agg["all_private_closed"]   = sorted(all_priv_closed)
        agg["all_public_closed"]    = sorted(all_pub_closed)
        agg["all_parameters"]       = sorted(all_params)
        agg["all_sensitive_params"] = sorted(all_sens_params)
        agg["total_endpoints"] = (
            len(all_priv_open) + len(all_pub_open) +
            len(all_priv_closed) + len(all_pub_closed)
        )
        return agg

    # =============================================================
    # PRINT SUMMARY
    # =============================================================
    def _print_summary(self, enum_result: dict, per_sub: dict, agg: dict):
        Logger.section("RECON SUMMARY")

        stats = enum_result["stats"]
        print(f"  Target                 : {self.target}")
        print(f"  Total subdomain found  : {stats['total_found']}")
        print(f"     LIVE                : {stats['live_count']}")
        print(f"     REACHABLE_EMPTY     : {stats['reachable_empty']}")
        print(f"     DNS_ONLY            : {stats['dns_only']}")
        print(f"     DEAD                : {stats['dead']}")
        print()
        print(f"  Subdomains crawled     : {agg['total_crawled_subs']}")
        print(f"  Total endpoints found  : {agg['total_endpoints']}")
        print()
        print(f"     PRIVATE-OPEN   : {len(agg['all_private_open'])}  (prioritas tinggi)")
        print(f"     PUBLIC-OPEN    : {len(agg['all_public_open'])}")
        print(f"     PRIVATE-CLOSED : {len(agg['all_private_closed'])}")
        print(f"     PUBLIC-CLOSED  : {len(agg['all_public_closed'])}")
        print()
        print(f"  Parameters found       : {len(agg['all_parameters'])}")
        print(f"     Sensitive           : {len(agg['all_sensitive_params'])}")

        # Sources breakdown
        Logger.section("SUBDOMAIN SOURCES")
        for src, count in stats["by_source_counts"].items():
            if count:
                print(f"  {src:<15}: {count}")

        # Top private_open findings (paling menarik)
        if agg["all_private_open"]:
            Logger.section("TOP FINDINGS - PRIVATE OPEN ENDPOINTS")
            for ep in agg["all_private_open"][:20]:
                print(f"  {ep}")
            if len(agg["all_private_open"]) > 20:
                print(f"  ... dan {len(agg['all_private_open']) - 20} lainnya (cek results/)")

    def close(self):
        self.finder.close()
