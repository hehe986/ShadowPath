#!/usr/bin/env python3

import argparse
import os
import time

from core.github_search import GitHubSearch
from core.repo_crawler import RepoCrawler
from core.downloader import Downloader

from scanner.endpoint_scanner import EndpointScanner
from scanner.parameter_scanner import ParameterScanner
from scanner.active_scanner import ActiveScanner
from scanner.crawl_scanner import CrawlScanner
from scanner.recon_scanner import ReconScanner

from filters.domain_filter import DomainFilter
from filters.endpoint_filter import EndpointFilter

from utils.banner import show_banner
from utils.logger import Logger
from utils.output import OutputFormatter
from utils.helpers import normalize_domain, is_valid_domain

import config


# =========================
# SETUP
# =========================
def create_results_dir():
    os.makedirs(config.RESULTS_DIR, exist_ok=True)


def resolve_token(arg_token: str, env_var: str, config_val: str) -> str:
    """Prioritas: CLI arg → env var → config file."""
    return arg_token or os.environ.get(env_var, "") or config_val or ""


# =========================
# 🔵 OSINT MODE
# =========================
def run_osint_scan(target: str, args) -> dict | None:
    Logger.section("OSINT MODE — Multi-Source Code Search")

    github_token  = resolve_token(args.token, "GITHUB_TOKEN", config.GITHUB_TOKEN)
    gitlab_token  = resolve_token(None, "GITLAB_TOKEN", config.GITLAB_TOKEN)

    github = GitHubSearch(
        token=github_token,
        gitlab_token=gitlab_token,
        bitbucket_user=config.BITBUCKET_USER,
        bitbucket_app_password=config.BITBUCKET_APP_PASSWORD,
    )
    crawler    = RepoCrawler(github_token=github_token)
    downloader = Downloader(delay_range=config.DELAY_RANGE)

    ep_scanner = EndpointScanner(
        target_domain=target,
        validate=not args.no_validate,
        delay_range=config.DELAY_RANGE,
    )
    param_scanner = ParameterScanner()

    # ── STEP 1: SEARCH ──
    sources = args.sources.split(",") if args.sources else config.SOURCES
    Logger.info(f"Sources: {', '.join(sources)}")

    queries = github.build_queries(target)
    Logger.info(f"Running {len(queries)} queries across {len(sources)} source(s)...")

    all_results = []
    for query in queries:
        found = github.search_all(
            query,
            per_page=config.GITHUB_PER_PAGE,
            sources=sources,
            bitbucket_workspace=config.BITBUCKET_WORKSPACE,
        )
        all_results.extend(found)

    # Deduplikasi raw results
    seen_raw = set()
    unique_results = []
    for r in all_results:
        key = r.get("raw_url", "")
        if key and key not in seen_raw:
            seen_raw.add(key)
            unique_results.append(r)

    Logger.success(f"Total unique files found: {len(unique_results)}")

    if not unique_results:
        Logger.warn("No source files found. Coba tambah --token atau ganti query.")
        return None

    # ── STEP 2: CRAWL REPOS ──
    if args.deep:
        Logger.info("Deep crawl enabled — scanning full repo file trees...")
        extra_files = crawler.crawl_repos(unique_results)
        unique_results.extend(extra_files)
        Logger.info(f"Total files after deep crawl: {len(unique_results)}")

    # ── STEP 3: DOWNLOAD ──
    Logger.info("Downloading file contents...")
    files = downloader.fetch_multiple(unique_results)
    Logger.success(f"Downloaded: {len(files)} files")

    if not files:
        Logger.warn("Tidak ada file yang berhasil didownload.")
        return None

    # ── STEP 4: SCAN ENDPOINTS ──
    Logger.info("Scanning endpoints...")
    if args.no_validate:
        endpoint_data = ep_scanner.scan_osint(files)
    else:
        endpoint_data = ep_scanner.scan(files)

    classified   = endpoint_data.get("classified", {})
    dup_analysis = endpoint_data.get("duplicate_analysis")
    scored       = endpoint_data.get("scored", [])
    raw_results  = endpoint_data.get("raw", [])

    # ── STEP 5: SCAN PARAMETERS ──
    Logger.info("Scanning parameters...")
    param_data = param_scanner.scan_and_attach(
        files,
        [ep for cat in classified.values() for ep in cat]
    )

    # ── STEP 6: OUTPUT ──
    OutputFormatter.print_summary(target, {
        "source_results": {
            "github":    sum(1 for r in unique_results if r.get("source") == "github"),
            "gitlab":    sum(1 for r in unique_results if r.get("source") == "gitlab"),
            "bitbucket": sum(1 for r in unique_results if r.get("source") == "bitbucket"),
        },
        "endpoints": {
            "total_extracted": endpoint_data.get("total_found", 0),
            "after_filter":    endpoint_data.get("total_after_filter", endpoint_data.get("total_found", 0)),
            "validated":       endpoint_data.get("total_validated", 0),
            "unique_response": len(dup_analysis.get("unique", [])) if dup_analysis else 0,
        },
        "parameters": {
            "total":     param_data.get("total", 0),
            "sensitive": len(param_data.get("sensitive", [])),
        },
    })

    OutputFormatter.print_results(classified, raw_results)

    if dup_analysis:
        OutputFormatter.print_duplicate_report(dup_analysis)

    OutputFormatter.print_parameters(param_data)

    if scored:
        OutputFormatter.print_scored(scored)

    return {
        "mode":          "osint",
        "source_count":  len(unique_results),
        "endpoint_data": endpoint_data,
        "classified":    classified,
        "dup_analysis":  dup_analysis,
        "parameters":    param_data,
        "raw":           raw_results,
    }


# =========================
# 🔴 ACTIVE MODE
# =========================
def run_active_scan(target: str, args) -> dict:
    Logger.section("ACTIVE SCAN MODE — Wordlist-based Discovery")

    wordlist = args.wordlist or config.WORDLIST_PATH
    threads  = args.threads  or config.THREADS
    timeout  = config.TIMEOUT

    if not os.path.exists(wordlist):
        Logger.error(f"Wordlist tidak ditemukan: {wordlist}")
        return {}

    scanner = ActiveScanner(
        domain=target,
        wordlist=wordlist,
        threads=threads,
        timeout=timeout,
    )

    result = scanner.scan()

    classified   = result.get("classified", {})
    dup_analysis = result.get("duplicate_analysis", {})
    raw_results  = result.get("raw", [])

    OutputFormatter.print_summary(target, {
        "endpoints": {
            "total_extracted": result.get("total_tested", 0),
            "after_filter":    result.get("total_tested", 0),
            "validated":       result.get("total_found", 0),
            "unique_response": len(dup_analysis.get("unique", [])),
        },
    })

    OutputFormatter.print_results(classified, raw_results)
    OutputFormatter.print_duplicate_report(dup_analysis)

    return {
        "mode":         "active",
        "classified":   classified,
        "dup_analysis": dup_analysis,
        "raw":          raw_results,
        "total_tested": result.get("total_tested", 0),
        "total_found":  result.get("total_found", 0),
    }


# =========================
# 💾 SAVE RESULTS
# =========================
def save_results(target: str, result: dict):
    if not result:
        return

    create_results_dir()

    classified   = result.get("classified", {})
    param_data   = result.get("parameters")
    dup_analysis = result.get("dup_analysis")
    mode         = result.get("mode", "unknown")

    # Build full JSON payload
    json_payload = {
        "meta": {
            "tool":    "ShadowPath Hidden Endpoint Discovery Engine",
            "version": "1.6.0",
            "target":  target,
            "mode":    mode,
        },
        "stats": {
            "source_count":  result.get("source_count", 0),
            "total_tested":  result.get("total_tested", 0),
            "total_found":   result.get("total_found", 0),
        },
        "endpoints":         classified,
        "duplicate_analysis": dup_analysis,
        "parameters":         param_data,
        "scored":             result.get("endpoint_data", {}).get("scored", []),
    }

    OutputFormatter.save_txt(
        config.ENDPOINTS_FILE,
        classified,
        param_data,
        dup_analysis,
        target,
    )

    OutputFormatter.save_json(config.JSON_FILE, json_payload)

    # Save parameters terpisah jika ada
    if param_data and param_data.get("all"):
        try:
            from utils.helpers import safe_write
            lines = [
                "# ShadowPath Parameter Results\n",
                f"# Target: {target}\n\n",
            ]
            if param_data.get("sensitive"):
                lines.append("# [SENSITIVE]\n")
                lines.extend(p + "\n" for p in sorted(param_data["sensitive"]))
                lines.append("\n")
            lines.append("# [ALL]\n")
            lines.extend(p + "\n" for p in sorted(param_data.get("all", [])))
            qs = param_data.get("query_string_template", "")
            if qs:
                lines.append(f"\n# Query template: {qs}\n")
            safe_write(config.PARAMETERS_FILE, "".join(lines))
            Logger.success(f"Saved: {config.PARAMETERS_FILE}")
        except Exception as e:
            Logger.error(f"Failed to save parameters: {e}")

    Logger.success(f"Results saved → {config.RESULTS_DIR}/")


# =========================
# 🕸️ CRAWL MODE
# =========================
def run_crawl_scan(target: str, args) -> dict:
    Logger.section("CRAWL MODE — Real-Time Web Spider")

    timing   = args.timing or config.STEALTH_TIMING
    validate = not args.no_validate

    scanner = CrawlScanner(
        target_domain=target,
        max_pages=args.max_pages or config.CRAWL_MAX_PAGES,
        max_depth=args.max_depth or config.CRAWL_MAX_DEPTH,
        timing_mode=timing,
        validate=validate,
        crawl_js=not args.no_js,
        follow_subdomains=args.follow_subs,
        timeout=config.REQUEST_TIMEOUT,
    )
    # DEBUG: disable interleave sementara untuk isolate bug
    scanner.crawler.session.interleave = False

    seed = args.seed or None
    Logger.info(f"Timing mode : {timing}")
    Logger.info(f"Max pages   : {args.max_pages or config.CRAWL_MAX_PAGES}")
    Logger.info(f"Max depth   : {args.max_depth or config.CRAWL_MAX_DEPTH}")
    Logger.info(f"Crawl JS    : {not args.no_js}")
    Logger.info(f"Validate    : {validate}")
    if seed:
        Logger.info(f"Seed URL    : {seed}")
    print()

    try:
        result = scanner.scan(seed_url=seed)
    finally:
        scanner.close()

    # Print summary stats
    cs = result.get("crawl_stats", {})
    OutputFormatter.print_summary(target, {
        "endpoints": {
            "total_extracted": result.get("total_found", 0),
            "after_filter":    result.get("total_after_filter", 0),
            "validated":       result.get("total_validated", 0),
            "unique_response": len(
                result.get("duplicate_analysis", {}).get("unique", [])
            ) if result.get("duplicate_analysis") else 0,
        },
        "parameters": {
            "total":     result.get("parameters", {}).get("total", 0),
            "sensitive": len(result.get("parameters", {}).get("sensitive", [])),
        },
    })

    # Print crawl stats detail
    if cs:
        Logger.section("CRAWL STATS")
        print(f"  Pages crawled   : {cs.get('pages_crawled', 0)}")
        print(f"  URLs found      : {cs.get('urls_found', 0)}")
        print(f"  JS files parsed : {cs.get('js_files', 0)}")
        print(f"  Forms found     : {cs.get('forms', 0)}")

    # Print stealth session stats
    if hasattr(scanner.crawler, 'session'):
        scanner.crawler.session.print_stats()

    return result


# =========================
# 🔎 RECON MODE (Subdomain + Crawl per subdomain)
# =========================
def run_recon_scan(target: str, args) -> dict:
    Logger.section("RECON MODE — Full Reconnaissance")

    timing = args.timing or config.STEALTH_TIMING

    max_subs   = args.max_subs      or config.RECON_MAX_SUBS
    pages_sub  = args.pages_per_sub or config.RECON_MAX_PAGES_PER_SUB
    depth_sub  = args.depth_per_sub or config.RECON_MAX_DEPTH_PER_SUB
    threads    = args.recon_threads or config.RECON_THREADS

    bruteforce   = not args.no_bruteforce
    permutation  = not args.no_permutation
    crawl_each   = not args.no_crawl
    skip_empty   = args.skip_empty or config.RECON_SKIP_EMPTY_HOSTS

    Logger.info(f"Timing mode        : {timing}")
    Logger.info(f"Max subdomains     : {max_subs}")
    Logger.info(f"Pages per subdomain: {pages_sub}")
    Logger.info(f"Depth per subdomain: {depth_sub}")
    Logger.info(f"Bruteforce         : {bruteforce}")
    Logger.info(f"Permutation        : {permutation}")
    Logger.info(f"Crawl each         : {crawl_each}")
    Logger.info(f"Skip empty hosts   : {skip_empty}")
    print()

    scanner = ReconScanner(
        target_domain=target,
        max_subs=max_subs,
        max_pages_per_sub=pages_sub,
        max_depth=depth_sub,
        timing_mode=timing,
        crawl_each=crawl_each,
        bruteforce=bruteforce,
        permutation=permutation,
        threads=threads,
        skip_empty=skip_empty,
    )

    try:
        result = scanner.scan()
    finally:
        scanner.close()

    # Save output per subdomain
    _save_recon_results(result)
    return result


def _save_recon_results(result: dict):
    """Save recon result ke file terpisah + JSON gabungan."""
    import json, os
    os.makedirs(config.RESULTS_DIR, exist_ok=True)

    # 1. Subdomains list (plain text)
    with open(config.SUBDOMAINS_FILE, "w", encoding="utf-8") as f:
        f.write(f"# ShadowPath - Subdomain Enumeration Results\n")
        f.write(f"# Target: {result['target']}\n")
        f.write(f"# Total found: {result['enum']['stats']['total_found']}\n")
        f.write(f"# Live: {result['enum']['stats']['live_count']}\n\n")

        f.write("=" * 60 + "\n[LIVE SUBDOMAINS]\n" + "=" * 60 + "\n")
        for detail in result["enum"]["live_details"]:
            if detail["status"] == "live":
                f.write(f"{detail['host']:<50} [{detail.get('server','?')}] {detail.get('title','')[:60]}\n")

        f.write("\n" + "=" * 60 + "\n[REACHABLE_EMPTY SUBDOMAINS]\n" + "=" * 60 + "\n")
        for detail in result["enum"]["live_details"]:
            if detail["status"] == "reachable_empty":
                f.write(f"{detail['host']:<50} {detail.get('reason','')[:60]}\n")

        f.write("\n" + "=" * 60 + "\n[DNS_ONLY SUBDOMAINS]\n" + "=" * 60 + "\n")
        for detail in result["enum"]["live_details"]:
            if detail["status"] == "dns_only":
                f.write(f"{detail['host']}\n")

    Logger.success(f"Saved: {config.SUBDOMAINS_FILE}")

    # 2. Endpoints per subdomain (categorized)
    agg = result["aggregated"]
    with open(config.ENDPOINTS_FILE, "w", encoding="utf-8") as f:
        f.write(f"# ShadowPath - Recon Endpoint Discovery Results\n")
        f.write(f"# Target: {result['target']}\n")
        f.write(f"# Total endpoints: {agg['total_endpoints']}\n\n")

        sections = [
            ("all_private_open",   "[PRIVATE-OPEN]   Endpoint sensitif TERBUKA - prioritas tinggi"),
            ("all_public_open",    "[PUBLIC-OPEN]    Endpoint umum, accessible"),
            ("all_private_closed", "[PRIVATE-CLOSED] Endpoint sensitif tertutup (401/403)"),
            ("all_public_closed",  "[PUBLIC-CLOSED]  Endpoint umum tidak accessible (404)"),
        ]

        for key, title in sections:
            items = agg.get(key, [])
            f.write("=" * 70 + f"\n{title} ({len(items)})\n" + "=" * 70 + "\n")
            for url in items:
                f.write(f"{url}\n")
            f.write("\n")

        # Per subdomain breakdown
        f.write("\n" + "=" * 70 + "\n[BREAKDOWN PER SUBDOMAIN]\n" + "=" * 70 + "\n")
        for host, data in result["subdomains"].items():
            eps = data.get("endpoints", {})
            total = sum(len(v) for v in eps.values())
            f.write(f"\n--- {host} ({total} endpoints) ---\n")
            for cat, urls in eps.items():
                if urls:
                    f.write(f"  [{cat}] {len(urls)} endpoints\n")
                    for u in urls[:10]:
                        f.write(f"    {u}\n")
                    if len(urls) > 10:
                        f.write(f"    ... +{len(urls) - 10} more\n")

    Logger.success(f"Saved: {config.ENDPOINTS_FILE}")

    # 3. Full JSON (untuk parsing programmatic)
    try:
        with open(config.RECON_FILE, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, default=str, ensure_ascii=False)
        Logger.success(f"Saved: {config.RECON_FILE}")
    except Exception as e:
        Logger.warn(f"JSON save error: {e}")


# =========================
# 🚀 MAIN
# =========================
def main():
    parser = argparse.ArgumentParser(
        description="ShadowPath v1.6.0 — Hidden Endpoint Discovery Engine",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument("-d", "--domain",
        required=True,
        help="Target domain (e.g. example.com)")
    parser.add_argument("-k", "--token",
        default="",
        help="GitHub API token")
    parser.add_argument("--sources",
        default="",
        help="Comma-separated sources: github,gitlab,bitbucket (default: from config)")
    parser.add_argument("--no-validate",
        action="store_true",
        help="Skip HTTP validation (OSINT only, no requests to target)")
    parser.add_argument("--active",
        action="store_true",
        help="Enable active wordlist-based scanning")
    parser.add_argument("--wordlist",
        default="",
        help="Custom wordlist path (active mode)")
    parser.add_argument("--threads",
        type=int,
        default=0,
        help="Thread count for active scan (default: from config)")
    parser.add_argument("--deep",
        action="store_true",
        help="Deep crawl: scan full file tree of discovered repos")
    parser.add_argument("--debug",
        action="store_true",
        help="Enable debug output")

    # ── CRAWL MODE ──
    crawl_grp = parser.add_argument_group("Crawl Mode (--crawl)")
    crawl_grp.add_argument("--crawl",
        action="store_true",
        help="Enable real-time web spider (crawl langsung ke target)")
    crawl_grp.add_argument("--seed",
        default="",
        help="Seed URL untuk crawler (default: https://<domain>/)")
    crawl_grp.add_argument("--max-pages",
        type=int, default=0,
        help=f"Maks halaman yang di-crawl (default: {config.CRAWL_MAX_PAGES})")
    crawl_grp.add_argument("--max-depth",
        type=int, default=0,
        help=f"Kedalaman spider dari seed (default: {config.CRAWL_MAX_DEPTH})")
    crawl_grp.add_argument("--timing",
        default="",
        choices=["fast", "normal", "slow", "random"],
        help="Timing mode untuk stealth (default: normal)\n"
             "  fast   = 0.3-1.5s  [aggressive]\n"
             "  normal = 1.0-4.0s  [recommended]\n"
             "  slow   = 3.0-8.0s  [maximum stealth]\n"
             "  random = mix acak")
    crawl_grp.add_argument("--no-js",
        action="store_true",
        help="Skip download dan parse file JS external")
    crawl_grp.add_argument("--follow-subs",
        action="store_true",
        help="Ikut crawl subdomain dari target domain")

    # ── RECON MODE ──
    recon_grp = parser.add_argument_group("Recon Mode (--recon)")
    recon_grp.add_argument("--recon",
        action="store_true",
        help="Full recon: enum subdomain + crawl per subdomain + classify 4-way")
    recon_grp.add_argument("--max-subs",
        type=int, default=0,
        help=f"Maks subdomain di-enum (default: {config.RECON_MAX_SUBS})")
    recon_grp.add_argument("--pages-per-sub",
        type=int, default=0,
        help=f"Maks halaman crawl per subdomain (default: {config.RECON_MAX_PAGES_PER_SUB})")
    recon_grp.add_argument("--depth-per-sub",
        type=int, default=0,
        help=f"Kedalaman crawl per subdomain (default: {config.RECON_MAX_DEPTH_PER_SUB})")
    recon_grp.add_argument("--recon-threads",
        type=int, default=0,
        help=f"Thread untuk enum (default: {config.RECON_THREADS})")
    recon_grp.add_argument("--no-bruteforce",
        action="store_true",
        help="Skip DNS bruteforce, hanya passive")
    recon_grp.add_argument("--no-permutation",
        action="store_true",
        help="Skip permutation dari found subdomains")
    recon_grp.add_argument("--no-crawl",
        action="store_true",
        help="Hanya list subdomain, skip crawl endpoint per subdomain")
    recon_grp.add_argument("--skip-empty",
        action="store_true",
        help="Skip crawl subdomain yang REACHABLE_EMPTY (hanya LIVE)")

    args = parser.parse_args()

    # Setup
    if args.debug:
        config.DEBUG_MODE = True
        from utils.logger import Logger as L
        L.DEBUG = True

    show_banner()

    # Validasi domain
    target = normalize_domain(args.domain)
    if not is_valid_domain(target):
        Logger.error(f"Domain tidak valid: {target}")
        return

    Logger.info(f"Target  : {target}")
    if args.recon:
        mode_label = "RECON"
    elif args.crawl:
        mode_label = "CRAWL"
    elif args.active:
        mode_label = "ACTIVE"
    else:
        mode_label = "OSINT"
    Logger.info(f"Mode    : {mode_label}")
    if args.no_validate:
        Logger.warn("Validation disabled — no HTTP requests to target")
    print()

    start_time = time.time()

    # ── RUN ──
    if args.recon:
        result = run_recon_scan(target, args)
    elif args.crawl:
        result = run_crawl_scan(target, args)
    elif args.active:
        result = run_active_scan(target, args)
    else:
        result = run_osint_scan(target, args)

    elapsed = time.time() - start_time

    # ── SAVE ──
    # Recon mode punya save handler sendiri (_save_recon_results)
    if config.SAVE_RESULTS and result and not args.recon:
        save_results(target, result)

    Logger.success(f"Scan completed in {elapsed:.1f}s")


if __name__ == "__main__":
    main()
