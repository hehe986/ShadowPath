# =========================================================
#          ShadowPath Configuration v3.0.0
# =========================================================

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
# CRAWL MODE (Real-Time)
# =========================
CRAWL_MAX_PAGES       = 100    # maksimum halaman yang di-crawl
CRAWL_MAX_DEPTH       = 4      # kedalaman spider dari seed
CRAWL_JS              = True   # ikut download dan parse JS external
CRAWL_FOLLOW_SUBS     = False  # ikut crawl subdomain

# =========================
# STEALTH / EVASION
# =========================
# "fast"   -> 0.3-1.5s  (aggressive)
# "normal" -> 1.0-4.0s  (recommended untuk CTF/bug bounty)
# "slow"   -> 3.0-8.0s  (untuk target sensitif / production)
# "random" -> mix acak
STEALTH_TIMING        = "normal"
STEALTH_ROTATE_UA     = True   # rotate UA setiap 8-20 request
STEALTH_INTERLEAVE    = True   # sesekali request favicon/robots sbg noise

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
