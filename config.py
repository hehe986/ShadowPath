# =========================================================
#          ShadowPath Configuration v3.1.0
# =========================================================

# =========================
# SOURCES (OSINT MODE)
# =========================
GITHUB_PER_PAGE  = 30
GITLAB_PER_PAGE  = 30
SOURCES          = ["github", "gitlab"]

# =========================
# CREDENTIALS (isi via env atau langsung)
# =========================
GITHUB_TOKEN           = ""
GITLAB_TOKEN           = ""
BITBUCKET_USER         = ""
BITBUCKET_APP_PASSWORD = ""
BITBUCKET_WORKSPACE    = ""

# =========================
# CRAWL MODE (Real-Time)
# =========================
CRAWL_MAX_PAGES       = 100
CRAWL_MAX_DEPTH       = 4
CRAWL_JS              = True
CRAWL_FOLLOW_SUBS     = False

# =========================
# RECON MODE (Subdomain + Crawl)
# =========================
RECON_MAX_SUBS          = 500
RECON_MAX_PAGES_PER_SUB = 20
RECON_MAX_DEPTH_PER_SUB = 3
RECON_BRUTEFORCE        = True
RECON_PERMUTATION       = True
RECON_THREADS           = 20
RECON_SKIP_EMPTY_HOSTS  = False

# =========================
# STEALTH / EVASION
# =========================
STEALTH_TIMING        = "normal"
STEALTH_ROTATE_UA     = True
STEALTH_INTERLEAVE    = True

# =========================
# PASSIVE SCAN (OSINT)
# =========================
VALIDATE_ENDPOINTS       = True
REQUEST_TIMEOUT          = 10
DELAY_BETWEEN_REQUESTS   = 1

# =========================
# ACTIVE SCAN
# =========================
WORDLIST_PATH   = "wordlists/endpoints.txt"
THREADS         = 10
TIMEOUT         = 8
MAX_RETRIES     = 2

INTERESTING_STATUS = [200, 201, 204, 301, 302, 307, 401, 403, 405, 500]

MIN_RESPONSE_LENGTH = 50
MAX_RESPONSE_LENGTH = 1_000_000

# =========================
# REQUEST SETTINGS
# =========================
VERIFY_SSL       = False
FOLLOW_REDIRECTS = True
RANDOM_UA        = True
DELAY_RANGE      = (1, 3)

# =========================
# FILTERS
# =========================
BLOCKED_KEYWORDS = [
    "localhost", "127.0.0.1", "0.0.0.0", "::1", ".local",
]

# =========================
# DUPLICATE DETECTION
# =========================
SIMILARITY_THRESHOLD = 0.92

# =========================
# OUTPUT
# =========================
SAVE_RESULTS    = True
RESULTS_DIR     = "results"
ENDPOINTS_FILE  = f"{RESULTS_DIR}/endpoints.txt"
PARAMETERS_FILE = f"{RESULTS_DIR}/parameters.txt"
JSON_FILE       = f"{RESULTS_DIR}/scan_results.json"
SUBDOMAINS_FILE = f"{RESULTS_DIR}/subdomains.txt"
RECON_FILE      = f"{RESULTS_DIR}/recon_results.json"

# =========================
# DEBUG
# =========================
DEBUG_MODE = False
