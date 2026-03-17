# ShadowPath Configuration

# =========================
# GITHUB
# =========================
GITHUB_PER_PAGE = 30


# =========================
# SCANNER (OSINT)
# =========================
VALIDATE_ENDPOINTS = True
REQUEST_TIMEOUT = 10
DELAY_BETWEEN_REQUESTS = 0


# =========================
# ACTIVE SCAN 🔥
# =========================
WORDLIST_PATH = "wordlists/endpoints.txt"
THREADS = 10
TIMEOUT = 5


# =========================
# FILTERS
# =========================
BLOCKED_KEYWORDS = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    ".local",
    "dev",
    "test"
]


# =========================
# OUTPUT
# =========================
SAVE_RESULTS = True
RESULTS_DIR = "results"

ENDPOINTS_FILE = f"{RESULTS_DIR}/endpoints.txt"
PARAMETERS_FILE = f"{RESULTS_DIR}/parameters.txt"
JSON_FILE = f"{RESULTS_DIR}/scan_results.json"
