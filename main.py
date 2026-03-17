#!/usr/bin/env python3

import argparse
import json
import os

from core.github_search import GitHubSearch
from core.repo_crawler import RepoCrawler
from core.downloader import Downloader

from scanner.endpoint_scanner import EndpointScanner
from scanner.parameter_scanner import ParameterScanner
from scanner.active_scanner import ActiveScanner  # 🆕 NEW

from filters.domain_filter import DomainFilter
from filters.endpoint_filter import EndpointFilter

from utils.banner import show_banner
from utils.logger import Logger
from utils.output import OutputFormatter

import config


def create_results_dir():
    if not os.path.exists(config.RESULTS_DIR):
        os.makedirs(config.RESULTS_DIR)


def save_json(data):
    try:
        with open(config.JSON_FILE, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        Logger.error(f"Failed to save JSON: {e}")


# =========================
# 🔵 OSINT MODE (GITHUB)
# =========================
def run_github_scan(target, args):

    Logger.info("Mode: OSINT (GitHub)")

    github = GitHubSearch(token=args.token)
    crawler = RepoCrawler()
    downloader = Downloader()

    endpoint_scanner = EndpointScanner(validate=not args.no_validate)
    parameter_scanner = ParameterScanner()

    domain_filter = DomainFilter(target)
    endpoint_filter = EndpointFilter()

    Logger.info("Searching GitHub...")

    results = github.search_code(target, per_page=config.GITHUB_PER_PAGE)

    Logger.success(f"GitHub Results: {len(results)} files")

    if not results:
        Logger.warn("No results found")
        return

    repos = crawler.extract_repos(results)
    Logger.info(f"Unique Repos: {len(repos)}")

    Logger.info("Downloading files...")
    files = downloader.fetch_multiple(results)

    Logger.success(f"Downloaded: {len(files)} files")

    if not files:
        Logger.warn("No files downloaded")
        return

    Logger.info("Scanning endpoints...")
    endpoint_data = endpoint_scanner.scan(files)

    endpoints = []
    for category in endpoint_data["classified"].values():
        endpoints.extend(category)

    endpoints = domain_filter.filter(endpoints)
    endpoints = endpoint_filter.filter(endpoints)

    classified = endpoint_scanner.classifier.classify_list(endpoints)

    Logger.info("Scanning parameters...")
    param_data = parameter_scanner.scan(files)

    OutputFormatter.print_summary(
        target,
        len(results),
        endpoint_data["total_found"]
    )

    OutputFormatter.print_results(classified)

    return {
        "results": results,
        "endpoint_data": endpoint_data,
        "classified": classified,
        "parameters": param_data
    }


# =========================
# 🔴 ACTIVE MODE (WEB SCAN)
# =========================
def run_active_scan(target):

    Logger.info("Mode: ACTIVE SCAN")

    scanner = ActiveScanner(
        domain=target,
        wordlist=config.WORDLIST_PATH,
        threads=config.THREADS,
        timeout=config.TIMEOUT
    )

    result = scanner.scan()

    classified = result["classified"]

    OutputFormatter.print_summary(
        target,
        result["total_tested"],
        result["total_found"]
    )

    OutputFormatter.print_results(classified)

    return result


# =========================
# 🚀 MAIN
# =========================
def main():

    parser = argparse.ArgumentParser(description="ShadowPath - Hidden Endpoint Finder")

    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-k", "--token", help="GitHub API token")
    parser.add_argument("--no-validate", action="store_true", help="Disable endpoint validation")

    # 🆕 NEW MODE
    parser.add_argument("--active", action="store_true", help="Enable active web scanning")

    args = parser.parse_args()

    target = args.domain.lower()

    show_banner()
    Logger.info(f"Target: {target}")

    # =========================
    # MODE SWITCH
    # =========================
    if args.active:
        result = run_active_scan(target)

        json_data = {
            "target": target,
            "mode": "active",
            "stats": {
                "total_tested": result["total_tested"],
                "total_found": result["total_found"]
            },
            "endpoints": result["classified"]
        }

    else:
        result = run_github_scan(target, args)

        if not result:
            return

        json_data = {
            "target": target,
            "mode": "osint",
            "stats": {
                "github_results": len(result["results"]),
                "total_endpoints": result["endpoint_data"]["total_found"],
                "valid_endpoints": result["endpoint_data"]["total_valid"]
            },
            "endpoints": result["classified"],
            "parameters": result["parameters"]
        }

    # =========================
    # SAVE RESULTS
    # =========================
    if config.SAVE_RESULTS:

        create_results_dir()

        OutputFormatter.save_to_file(config.ENDPOINTS_FILE, json_data["endpoints"])

        save_json(json_data)

        Logger.success("Results saved in /results")

    Logger.success("Scan completed")


if __name__ == "__main__":
    main()
