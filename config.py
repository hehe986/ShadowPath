# =========================
# ShadowPath Configuration
# =========================


# =========================
# GITHUB (OSINT MODE)
# =========================
GITHUB_PER_PAGE = 30


# =========================
# PASSIVE SCAN (OSINT)
# =========================
VALIDATE_ENDPOINTS = True
REQUEST_TIMEOUT = 10
DELAY_BETWEEN_REQUESTS = 0


# =========================
# ACTIVE SCAN 🔥
# =========================
WORDLIST_PATH = "wordlists/endpoints.txt"

THREADS = 20          # 🔥 default dinaikkan (lebih cepat)
TIMEOUT = 8           # 🔥 lebih realistis (biar gak banyak timeout)

# Retry kalau gagal
MAX_RETRIES = 2

# Status code yang dianggap menarik
INTERESTING_STATUS = [200, 204, 301, 302, 307, 401, 403]

# Filter berdasarkan panjang response (anti false positive)
MIN_RESPONSE_LENGTH = 50
MAX_RESPONSE_LENGTH = 1000000


# =========================
# REQUEST SETTINGS
# =========================
VERIFY_SSL = False     # 🔥 disable SSL verify
FOLLOW_REDIRECTS = True

# Random User-Agent
RANDOM_UA = True

# Delay random (anti WAF / rate limit)
RANDOM_DELAY = (0, 0.3)


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


# =========================
# DEBUG
# =========================
DEBUG_MODE = False
