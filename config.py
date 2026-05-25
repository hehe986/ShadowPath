# ╔══════════════════════════════════════════════════════╗
# ║           ShadowPath Configuration v1.5.0            ║
# ╚══════════════════════════════════════════════════════╝

# =========================
# SOURCES (OSINT MODE)
# =========================
GITHUB_PER_PAGE  = 30
GITLAB_PER_PAGE  = 30
SOURCES          = ["github", "gitlab"]   # aktifkan bitbucket jika perlu

# =========================
# CREDENTIALS (isi via env atau langsung)
# =========================
GITHUB_TOKEN           = ""   # atau set env GITHUB_TOKEN
GITLAB_TOKEN           = ""   # atau set env GITLAB_TOKEN
BITBUCKET_USER         = ""
BITBUCKET_APP_PASSWORD = ""
BITBUCKET_WORKSPACE    = ""

# =========================
# PASSIVE SCAN (OSINT)
# =========================
VALIDATE_ENDPOINTS       = True
REQUEST_TIMEOUT          = 10
DELAY_BETWEEN_REQUESTS   = 1   # detik, 0 = tanpa delay

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
DELAY_RANGE      = (1, 3)   # detik, random per request

# =========================
# FILTERS
# =========================
BLOCKED_KEYWORDS = [
    "localhost", "127.0.0.1", "0.0.0.0", "::1", ".local",
]

# =========================
# DUPLICATE DETECTION
# =========================
SIMILARITY_THRESHOLD = 0.92   # 0.0 - 1.0

# =========================
# OUTPUT
# =========================
SAVE_RESULTS    = True
RESULTS_DIR     = "results"
ENDPOINTS_FILE  = f"{RESULTS_DIR}/endpoints.txt"
PARAMETERS_FILE = f"{RESULTS_DIR}/parameters.txt"
JSON_FILE       = f"{RESULTS_DIR}/scan_results.json"

# =========================
# DEBUG
# =========================
DEBUG_MODE = False
