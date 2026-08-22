"""
core/browser_renderer.py - Headless Browser Renderer (SPA Support)
===================================================================
Render halaman pakai Chromium headless (via Playwright) untuk website SPA.

CATATAN TEKNIS (Windows fix):
  Playwright Sync API tidak bisa jalan di dalam asyncio event loop.
  Semua operasi Playwright dijalankan di THREAD TERPISAH yang punya loop
  sendiri, menghindari error "Sync API inside the asyncio loop".
"""

import threading
import queue

from utils.logger import Logger


try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class BrowserRenderer:
    """Render SPA pakai headless Chromium (thread-isolated untuk hindari konflik asyncio)."""

    def __init__(self, timeout: int = 20, wait_after_load: float = 2.0,
                 auto_scroll: bool = True, capture_api: bool = True,
                 user_agent: str = ""):
        self.timeout          = timeout * 1000  # ms
        self.wait_after_load  = wait_after_load
        self.auto_scroll      = auto_scroll
        self.capture_api      = capture_api
        self.user_agent       = user_agent

        self._thread   = None
        self._cmd_q    = queue.Queue()
        self._result_q = queue.Queue()
        self._started  = False

    @staticmethod
    def is_available() -> bool:
        return PLAYWRIGHT_AVAILABLE

    def start(self) -> bool:
        if not PLAYWRIGHT_AVAILABLE:
            Logger.warn("Playwright tidak terinstall - SPA rendering dinonaktifkan")
            Logger.warn("Install: pip install playwright && playwright install chromium")
            return False
        if self._started:
            return True

        ready_q = queue.Queue()
        self._thread = threading.Thread(target=self._worker, args=(ready_q,), daemon=True)
        self._thread.start()
        try:
            ok, err = ready_q.get(timeout=60)
        except queue.Empty:
            Logger.warn("Timeout menunggu browser start")
            return False
        if not ok:
            Logger.warn(f"Gagal start browser: {err}")
            Logger.warn("Pastikan sudah run: playwright install chromium")
            return False
        self._started = True
        return True

    def stop(self):
        if self._thread and self._thread.is_alive():
            self._cmd_q.put(None)
            self._thread.join(timeout=10)
        self._started = False

    def _worker(self, ready_q):
        playwright = None
        browser = None
        try:
            playwright = sync_playwright().start()
            browser = playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-blink-features=AutomationControlled",
                      "--disable-dev-shm-usage"],
            )
            ready_q.put((True, None))
        except Exception as e:
            ready_q.put((False, str(e)))
            try:
                if browser: browser.close()
            except Exception: pass
            try:
                if playwright: playwright.stop()
            except Exception: pass
            return

        while True:
            cmd = self._cmd_q.get()
            if cmd is None:
                break
            result = self._do_render(browser, cmd)
            self._result_q.put(result)

        try:
            browser.close()
        except Exception: pass
        try:
            playwright.stop()
        except Exception: pass

    def _do_render(self, browser, url: str) -> dict:
        result = {"url": url, "status": None, "html": "", "links": [],
                  "api_endpoints": [], "error": None}
        context = None
        page = None
        api_calls = set()
        try:
            ctx_opts = {"ignore_https_errors": True}
            if self.user_agent:
                ctx_opts["user_agent"] = self.user_agent
            context = browser.new_context(**ctx_opts)
            page = context.new_page()

            if self.capture_api:
                def on_request(request):
                    if request.resource_type in ("xhr", "fetch"):
                        api_calls.add(request.url)
                page.on("request", on_request)

            response = page.goto(url, timeout=self.timeout, wait_until="domcontentloaded")
            result["status"] = response.status if response else None
            try:
                page.wait_for_load_state("networkidle", timeout=self.timeout)
            except Exception:
                pass
            if self.wait_after_load:
                page.wait_for_timeout(int(self.wait_after_load * 1000))
            if self.auto_scroll:
                self._scroll_page(page)

            result["html"] = page.content()
            links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
            result["links"] = list(set(links))
            result["api_endpoints"] = list(api_calls)
        except Exception as e:
            result["error"] = str(e)
        finally:
            try:
                if page: page.close()
            except Exception: pass
            try:
                if context: context.close()
            except Exception: pass
        return result

    def _scroll_page(self, page):
        try:
            page.evaluate("""
                async () => {
                    await new Promise((resolve) => {
                        let total = 0; const step = 400;
                        const timer = setInterval(() => {
                            window.scrollBy(0, step); total += step;
                            if (total >= document.body.scrollHeight || total > 8000) {
                                clearInterval(timer); resolve();
                            }
                        }, 200);
                    });
                }
            """)
            page.wait_for_timeout(500)
        except Exception:
            pass

    def render(self, url: str) -> dict:
        if not self._started:
            return {"url": url, "status": None, "html": "", "links": [],
                    "api_endpoints": [], "error": "browser not started"}
        self._cmd_q.put(url)
        try:
            return self._result_q.get(timeout=(self.timeout / 1000) + 30)
        except queue.Empty:
            return {"url": url, "status": None, "html": "", "links": [],
                    "api_endpoints": [], "error": "render timeout"}

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()
