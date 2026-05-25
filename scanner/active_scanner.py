import threading
from queue import Queue, Empty
from core.web_requester import WebRequester
from core.classifier import EndpointClassifier
from core.validator import EndpointValidator
from utils.logger import Logger


class ActiveScanner:
    def __init__(self, domain, wordlist, threads=10, timeout=5):
        self.domain = domain.rstrip("/")
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout

        self.queue = Queue()
        self.results = []
        self._lock = threading.Lock()

        self.requester = WebRequester(timeout=self.timeout)
        self.classifier = EndpointClassifier()
        self.validator = EndpointValidator(timeout=self.timeout)

        self._tested = 0
        self._found = 0

        # Baseline soft 404 detection
        self._baseline_fingerprint = None
        self._baseline_length = None
        self._baseline_tolerance = 50  # toleransi selisih length (bytes)

    # =========================
    # 📂 LOAD WORDLIST
    # =========================
    def load_wordlist(self) -> list:
        try:
            with open(self.wordlist, "r", encoding="utf-8") as f:
                lines = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        lines.append(line)
            Logger.info(f"Wordlist loaded: {len(lines)} paths")
            return lines
        except FileNotFoundError:
            Logger.error(f"Wordlist not found: {self.wordlist}")
            return []
        except Exception as e:
            Logger.error(f"Failed to load wordlist: {e}")
            return []

    # =========================
    # 🧪 BASELINE FINGERPRINT
    # Request ke path yang pasti tidak ada
    # untuk tahu seperti apa soft 404 di server ini
    # =========================
    def _fetch_baseline(self):
        import random, string
        random_path = ''.join(random.choices(string.ascii_lowercase, k=12))
        url = f"https://{self.domain}/{random_path}_shadowpath_test"
        Logger.info(f"Fetching baseline (soft 404 fingerprint)...")
        result = self.requester.request(url)
        if result and result.get("status_code") == 200:
            self._baseline_fingerprint = result.get("fingerprint", "")
            self._baseline_length = result.get("content_length", 0)
            Logger.warn(
                f"Server return 200 untuk path random "
                f"(soft 404 detected, len:{self._baseline_length}) — "
                f"akan difilter otomatis"
            )
        else:
            Logger.info("Baseline OK — server return non-200 untuk path tidak ada")

    # =========================
    # 🔍 CEK SOFT 404
    # =========================
    def _is_soft_404(self, result: dict) -> bool:
        """Return True jika response mirip dengan baseline (soft 404)."""
        if self._baseline_fingerprint is None:
            return False

        # Exact fingerprint match
        if result.get("fingerprint") == self._baseline_fingerprint:
            return True

        # Content length sangat mirip baseline
        if self._baseline_length is not None:
            diff = abs(result.get("content_length", 0) - self._baseline_length)
            if diff <= self._baseline_tolerance:
                return True

        return False

    # =========================
    # ⚙️ WORKER THREAD
    # =========================
    def worker(self):
        while True:
            try:
                path = self.queue.get(timeout=1)
            except Empty:
                break

            try:
                url = f"https://{self.domain}/{path.lstrip('/')}"

                if not self.validator.is_valid(url):
                    self.queue.task_done()
                    continue

                result = self.requester.request(url)

                with self._lock:
                    self._tested += 1

                if result and result.get("status_code"):
                    status = result["status_code"]

                    if status in [200, 201, 301, 302, 307, 401, 403, 405, 500]:

                        # Filter soft 404
                        if status == 200 and self._is_soft_404(result):
                            Logger.debug(f"[SOFT 404 filtered] {url}")
                            self.queue.task_done()
                            continue

                        entry = {
                            "url": url,
                            "status_code": status,
                            "content_length": result.get("content_length", 0),
                            "fingerprint": result.get("fingerprint", ""),
                            "content": result.get("content", ""),
                            "redirect_url": result.get("redirect_url"),
                            "server": result.get("server", ""),
                            "response_time": result.get("response_time", 0),
                        }

                        with self._lock:
                            self._found += 1
                            self.results.append(entry)

                        redirect_info = f" → {result.get('redirect_url')}" if result.get("redirect_url") else ""
                        Logger.info(
                            f"[{status}] {url} "
                            f"(len:{result.get('content_length', 0)}, "
                            f"{result.get('response_time', 0):.2f}s)"
                            f"{redirect_info}"
                        )

            except Exception as e:
                Logger.debug(f"Worker error on {path}: {e}")
            finally:
                self.queue.task_done()

    # =========================
    # 🚀 RUN SCAN
    # =========================
    def scan(self) -> dict:
        Logger.info(f"Starting active scan → {self.domain}")
        paths = self.load_wordlist()

        if not paths:
            Logger.warn("Wordlist empty or not found")
            return self._empty_result(0)

        # Fetch baseline dulu sebelum scan
        self._fetch_baseline()

        for path in paths:
            self.queue.put(path)

        thread_list = []
        actual_threads = min(self.threads, len(paths))
        for _ in range(actual_threads):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            thread_list.append(t)

        self.queue.join()

        Logger.success(f"Scan complete — tested: {self._tested}, found: {self._found}")

        if not self.results:
            Logger.warn("Semua hasil difilter sebagai soft 404 atau tidak ada yang menarik")
            return self._empty_result(len(paths))

        # Classify
        classified = self.classifier.classify_status(self.results)

        # Duplicate detection — tampilkan endpoint yang benar-benar berbeda
        dup_analysis = self.validator.detect_duplicates(self.results)

        Logger.section("HASIL UNIK (response berbeda)")
        for url in dup_analysis.get("unique", []):
            item = next((r for r in self.results if r["url"] == url), {})
            Logger.finding(
                item.get("status_code", 0),
                url,
                f"len:{item.get('content_length', 0)}"
            )

        if dup_analysis["warnings"]:
            Logger.section("DUPLICATE / SIMILAR WARNINGS")
            for url, msg in dup_analysis["warnings"].items():
                Logger.warning_duplicate(msg)

        return {
            "total_tested": len(paths),
            "total_found": self._found,
            "classified": classified,
            "duplicate_analysis": dup_analysis,
            "raw": self.results,
        }

    # =========================
    # 📊 HELPER
    # =========================
    def _empty_result(self, total_tested: int) -> dict:
        return {
            "total_tested": total_tested,
            "total_found": 0,
            "classified": {"public": [], "hidden": [], "sensitive": []},
            "duplicate_analysis": {
                "unique": [], "duplicate_groups": [],
                "similar_pairs": [], "warnings": {},
                "summary": {"total_checked": 0, "unique": 0,
                            "exact_duplicates": 0, "similar_pairs": 0,
                            "duplicate_groups": 0}
            },
            "raw": [],
        }

    def get_progress(self) -> dict:
        with self._lock:
            return {
                "tested": self._tested,
                "found": self._found,
                "queue_remaining": self.queue.qsize(),
            }
