#!/usr/bin/env python3

import argparse
import json
import os

from core.github_search import GitHubSearch
from core.repo_crawler import RepoCrawler
from core.downloader import Downloader

from scanner.endpoint_scanner import EndpointScanner
from scanner.parameter_scanner import ParameterScanner

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


def main():

    parser = argparse.ArgumentParser(description="ShadowPath - Hidden Endpoint Finder")

    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-k", "--token", help="GitHub API token")
    parser.add_argument("--no-validate", action="store_true", help="Disable endpoint validation")

    args = parser.parse_args()

    target = args.domain.lower()

    show_banner()

    Logger.info(f"Target: {target}")

    # Initialize modules
    github = GitHubSearch(token=args.token)
    crawler = RepoCrawler()
    downloader = Downloader()

    endpoint_scanner = EndpointScanner(validate=not args.no_validate)
    parameter_scanner = ParameterScanner()

    domain_filter = DomainFilter(target)
    endpoint_filter = EndpointFilter()

    # Step 1: Search GitHub
    Logger.info("Searching GitHub...")

    results = github.search_code(target, per_page=config.GITHUB_PER_PAGE)

    Logger.success(f"GitHub Results: {len(results)} files")

    if not results:
        Logger.warn("No results found")
        return

    # Step 2: Crawl repos
    repos = crawler.extract_repos(results)

    Logger.info(f"Unique Repos: {len(repos)}")

    # Step 3: Download files
    Logger.info("Downloading files...")

    files = downloader.fetch_multiple(results)

    Logger.success(f"Downloaded: {len(files)} files")

    if not files:
        Logger.warn("No files downloaded")
        return

    # Step 4: Scan endpoints
    Logger.info("Scanning endpoints...")

    endpoint_data = endpoint_scanner.scan(files)

    endpoints = []
    for category in endpoint_data["classified"].values():
        endpoints.extend(category)

    # Step 5: Filter domain
    endpoints = domain_filter.filter(endpoints)

    # Step 6: Clean endpoints
    endpoints = endpoint_filter.filter(endpoints)

    # Step 7: Re-classify after filtering
    classified = endpoint_scanner.classifier.classify_list(endpoints)

    # Step 8: Scan parameters
    Logger.info("Scanning parameters...")

    param_data = parameter_scanner.scan(files)

    # Step 9: Output
    OutputFormatter.print_summary(
        target,
        len(results),
        endpoint_data["total_found"]
    )

    OutputFormatter.print_results(classified)

    # Step 10: Save results
    if config.SAVE_RESULTS:

        create_results_dir()

        OutputFormatter.save_to_file(config.ENDPOINTS_FILE, classified)

        # Save parameters
        try:
            with open(config.PARAMETERS_FILE, "w") as f:
                for p in param_data["all"]:
                    f.write(p + "\n")
        except Exception as e:
            Logger.error(f"Failed to save parameters: {e}")

        # Save JSON
        json_data = {
            "target": target,
            "stats": {
                "github_results": len(results),
                "total_endpoints": endpoint_data["total_found"],
                "valid_endpoints": endpoint_data["total_valid"]
            },
            "endpoints": classified,
            "parameters": param_data
        }

        save_json(json_data)

        Logger.success("Results saved in /results")

    Logger.success("Scan completed")


if __name__ == "__main__":
    main()