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
        self._lock = threading.Lock()  # ✅ Fix race condition

        self.requester = WebRequester(timeout=self.timeout)
        self.classifier = EndpointClassifier()
        self.validator = EndpointValidator(timeout=self.timeout)

        # Counter untuk progress real-time
        self._tested = 0
        self._found = 0

    # =========================
    # 📂 LOAD WORDLIST
    # =========================
    def load_wordlist(self) -> list:
        try:
            with open(self.wordlist, "r", encoding="utf-8") as f:
                lines = []
                for line in f:
                    line = line.strip()
                    # Skip comment dan baris kosong
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

                # Skip jika URL tidak valid
                if not self.validator.is_valid(url):
                    self.queue.task_done()
                    continue

                result = self.requester.request(url)

                with self._lock:
                    self._tested += 1

                if result and result.get("status_code"):
                    status = result["status_code"]

                    if status in [200, 201, 301, 302, 307, 401, 403, 405, 500]:
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

                        # Real-time output
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

        # Isi queue
        for path in paths:
            self.queue.put(path)

        # Start threads
        thread_list = []
        actual_threads = min(self.threads, len(paths))
        for _ in range(actual_threads):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            thread_list.append(t)

        # Tunggu queue selesai
        self.queue.join()

        Logger.success(f"Scan complete — tested: {self._tested}, found: {self._found}")

        if not self.results:
            return self._empty_result(len(paths))

        # =========================
        # CLASSIFY
        # =========================
        classified = self.classifier.classify_status(self.results)

        # =========================
        # DUPLICATE DETECTION
        # =========================
        dup_analysis = self.validator.detect_duplicates(self.results)

        # Print duplicate report jika ada
        if dup_analysis["duplicate_groups"] or dup_analysis["similar_pairs"]:
            self.validator.print_duplicate_report(dup_analysis)

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
        """Return progress saat ini (bisa dipanggil dari thread lain)."""
        with self._lock:
            return {
                "tested": self._tested,
                "found": self._found,
                "queue_remaining": self.queue.qsize(),
            }
