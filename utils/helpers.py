import re
from urllib.parse import urlparse, urljoin


# =========================
# 🔗 URL HELPERS
# =========================
def clean_url(url: str) -> str | None:
    """Bersihkan URL dari whitespace dan double slash."""
    if not url:
        return None
    url = url.strip()
    # Hapus double slash kecuali setelah protokol (http://)
    url = re.sub(r'(?<!:)//+', '/', url)
    return url


def normalize_domain(domain: str) -> str:
    """Strip protokol, path, port dari domain."""
    domain = domain.lower().strip()
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.split("/")[0]
    domain = domain.split("?")[0]
    return domain


def build_url(domain: str, path: str) -> str:
    """Gabungkan domain dan path jadi URL lengkap."""
    base = domain.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base
    path = "/" + path.lstrip("/")
    return base + path


def extract_domain(url: str) -> str | None:
    """Extract domain dari URL lengkap."""
    try:
        return urlparse(url).netloc.lower() or None
    except Exception:
        return None


def is_same_domain(url_a: str, url_b: str) -> bool:
    """Cek apakah dua URL berasal dari domain yang sama."""
    return extract_domain(url_a) == extract_domain(url_b)


def strip_query(url: str) -> str:
    """Hapus query string dari URL."""
    try:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    except Exception:
        return url


# =========================
# 📋 LIST HELPERS
# =========================
def deduplicate(data: list) -> list:
    """Deduplikasi list, pertahankan urutan."""
    seen = set()
    result = []
    for item in data:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def sort_list(data: list) -> list:
    return sorted(data)


def chunk_list(data: list, size: int) -> list:
    """Pecah list jadi beberapa chunk ukuran tertentu."""
    return [data[i:i + size] for i in range(0, len(data), size)]


def flatten(nested: list) -> list:
    """Flatten list of lists jadi single list."""
    result = []
    for item in nested:
        if isinstance(item, list):
            result.extend(item)
        else:
            result.append(item)
    return result


# =========================
# ✅ VALIDATION HELPERS
# =========================
def is_valid_string(s: str, min_length: int = 3) -> bool:
    if not s:
        return False
    return len(s.strip()) >= min_length


def is_valid_url(url: str) -> bool:
    """Cek apakah string adalah URL yang valid."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def is_valid_domain(domain: str) -> bool:
    """Cek apakah string adalah domain yang valid."""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    d = normalize_domain(domain)
    return bool(re.match(pattern, d))


# =========================
# 📁 FILE HELPERS
# =========================
def read_lines(filepath: str, skip_comments: bool = True) -> list:
    """
    Baca file baris per baris.
    skip_comments: abaikan baris yang diawali #
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = []
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if skip_comments and line.startswith("#"):
                    continue
                lines.append(line)
        return lines
    except FileNotFoundError:
        return []
    except Exception:
        return []


def safe_write(filepath: str, content: str) -> bool:
    """Tulis file, return True jika berhasil."""
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return True
    except Exception:
        return False


# =========================
# 🎨 FORMAT HELPERS
# =========================
def truncate(s: str, max_len: int = 80, suffix: str = "...") -> str:
    """Potong string jika terlalu panjang."""
    if len(s) <= max_len:
        return s
    return s[:max_len - len(suffix)] + suffix


def status_label(code: int) -> str:
    """Return label human-readable untuk HTTP status code."""
    labels = {
        200: "OK",
        201: "Created",
        204: "No Content",
        301: "Moved Permanently",
        302: "Found (Redirect)",
        307: "Temporary Redirect",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        429: "Too Many Requests",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
    }
    return labels.get(code, f"HTTP {code}")
