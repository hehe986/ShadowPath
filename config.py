# ShadowPath Configuration

# GitHub
GITHUB_PER_PAGE = 30

# Scanner
VALIDATE_ENDPOINTS = True
REQUEST_TIMEOUT = 10
DELAY_BETWEEN_REQUESTS = 0

# Filters
BLOCKED_KEYWORDS = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    ".local",
    "dev",
    "test"
]

# Output
SAVE_RESULTS = True
RESULTS_DIR = "results"

ENDPOINTS_FILE = f"{RESULTS_DIR}/endpoints.txt"
PARAMETERS_FILE = f"{RESULTS_DIR}/parameters.txt"
JSON_FILE = f"{RESULTS_DIR}/scan_results.json"