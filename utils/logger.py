import datetime


class Logger:
    DEBUG = False  # toggle debug mode

    # ANSI color codes
    _RESET  = "\033[0m"
    _GREEN  = "\033[92m"
    _YELLOW = "\033[93m"
    _RED    = "\033[91m"
    _CYAN   = "\033[96m"
    _GRAY   = "\033[90m"
    _BOLD   = "\033[1m"

    @staticmethod
    def _ts() -> str:
        return datetime.datetime.now().strftime("%H:%M:%S")

    @staticmethod
    def info(message: str):
        print(f"{Logger._CYAN}[+]{Logger._RESET} {message}")

    @staticmethod
    def warn(message: str):
        print(f"{Logger._YELLOW}[!]{Logger._RESET} {message}")

    @staticmethod
    def error(message: str):
        print(f"{Logger._RED}[x]{Logger._RESET} {message}")

    @staticmethod
    def success(message: str):
        print(f"{Logger._GREEN}[✓]{Logger._RESET} {message}")

    @staticmethod
    def debug(message: str):
        if Logger.DEBUG:
            print(f"{Logger._GRAY}[DEBUG {Logger._ts()}]{Logger._RESET} {message}")

    @staticmethod
    def finding(status_code: int, url: str, extra: str = ""):
        """Khusus untuk print hasil endpoint yang ditemukan."""
        if status_code == 200:
            color = Logger._GREEN
        elif status_code in (401, 403):
            color = Logger._YELLOW
        elif status_code in (301, 302, 307):
            color = Logger._CYAN
        elif status_code == 500:
            color = Logger._RED
        else:
            color = Logger._RESET

        badge = f"{color}[{status_code}]{Logger._RESET}"
        extra_str = f" {Logger._GRAY}{extra}{Logger._RESET}" if extra else ""
        print(f"  {badge} {url}{extra_str}")

    @staticmethod
    def section(title: str):
        """Print section header."""
        print(f"\n{Logger._BOLD}{'─' * 50}{Logger._RESET}")
        print(f"{Logger._BOLD}  {title}{Logger._RESET}")
        print(f"{Logger._BOLD}{'─' * 50}{Logger._RESET}")

    @staticmethod
    def warning_duplicate(msg: str):
        print(f"  {Logger._YELLOW}⚠️  {msg}{Logger._RESET}")

    @staticmethod
    def timestamp() -> str:
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
