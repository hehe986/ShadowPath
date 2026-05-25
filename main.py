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
            "version": "2.0.0",
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
# 🚀 MAIN
# =========================
def main():
    parser = argparse.ArgumentParser(
        description="ShadowPath v2.0.0 — Hidden Endpoint Discovery Engine",
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
    Logger.info(f"Mode    : {'ACTIVE' if args.active else 'OSINT'}")
    if args.no_validate:
        Logger.warn("Validation disabled — no HTTP requests to target")
    print()

    start_time = time.time()

    # ── RUN ──
    if args.active:
        result = run_active_scan(target, args)
    else:
        result = run_osint_scan(target, args)

    elapsed = time.time() - start_time

    # ── SAVE ──
    if config.SAVE_RESULTS and result:
        save_results(target, result)

    Logger.success(f"Scan completed in {elapsed:.1f}s")


if __name__ == "__main__":
    main()
