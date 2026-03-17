import threading
from queue import Queue

from core.web_requester import WebRequester
from core.classifier import EndpointClassifier
from utils.logger import Logger


class ActiveScanner:

    def __init__(self, domain, wordlist, threads=10, timeout=5):
        self.domain = domain
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout

        self.queue = Queue()
        self.results = []

        self.requester = WebRequester(timeout=self.timeout)
        self.classifier = EndpointClassifier()

    # =========================
    # LOAD WORDLIST
    # =========================
    def load_wordlist(self):
        try:
            with open(self.wordlist, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            Logger.error(f"Failed to load wordlist: {e}")
            return []

    # =========================
    # WORKER THREAD
    # =========================
    def worker(self):
        while not self.queue.empty():

            path = self.queue.get()

            url = f"https://{self.domain}/{path}"

            result = self.requester.request(url)

            if result and result["status_code"]:

                status = result["status_code"]

                # hanya ambil response menarik
                if status < 500:

                    Logger.info(f"[{status}] {url}")

                    self.results.append({
                        "url": url,
                        "status_code": status
                    })

            self.queue.task_done()

    # =========================
    # RUN SCAN
    # =========================
    def scan(self):

        Logger.info("Starting active scan...")

        paths = self.load_wordlist()

        if not paths:
            Logger.warn("Wordlist empty")
            return {
                "total_tested": 0,
                "total_found": 0,
                "classified": {"public": [], "hidden": []}
            }

        for path in paths:
            self.queue.put(path)

        threads = []

        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)

        self.queue.join()

        Logger.success(f"Total tested: {len(paths)}")
        Logger.success(f"Total found: {len(self.results)}")

        # =========================
        # CLASSIFY
        # =========================
        classified = self.classifier.classify_status(self.results)

        return {
            "total_tested": len(paths),
            "total_found": len(self.results),
            "classified": classified
        }
