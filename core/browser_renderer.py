"""
core/browser_renderer.py - Headless Browser Renderer (SPA Support)
===================================================================
Render halaman pakai Chromium headless (via Playwright) untuk website SPA
yang kontennya di-generate JavaScript. Setelah JS jalan, ambil HTML final
yang sudah lengkap dengan semua link/konten.

Dependency: playwright + chromium
Install:
  pip install playwright
  playwright install chromium

Kalau Playwright TIDAK terinstall, module ini gracefully degrade —
crawler tetap jalan pakai HTTP biasa, cuma ga bisa render SPA.
"""

from utils.logger import Logger


try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class BrowserRenderer:
    """Render SPA pakai headless Chromium."""

    def __init__(self, timeout: int = 20, wait_after_load: float = 2.0,
                 auto_scroll: bool = True, capture_api: bool = True,
                 user_agent: str = ""):
        self.timeout          = timeout * 1000  # playwright pakai ms
        self.wait_after_load  = wait_after_load
        self.auto_scroll      = auto_scroll
        self.capture_api      = capture_api
        self.user_agent       = user_agent
        self._playwright = None
        self._browser    = None

    @staticmethod
    def is_available() -> bool:
        return PLAYWRIGHT_AVAILABLE

    def start(self) -> bool:
        if not PLAYWRIGHT_AVAILABLE:
            Logger.warn("Playwright tidak terinstall — SPA rendering dinonaktifkan")
            Logger.warn("Install: pip install playwright && playwright install chromium")
            return False
        try:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-blink-features=AutomationControlled",
                      "--disable-dev-shm-usage"],
            )
            return True
        except Exception as e:
            Logger.warn(f"Gagal start browser: {e}")
            Logger.warn("Pastikan sudah run: playwright install chromium")
            self._cleanup()
            return False

    def stop(self):
        self._cleanup()

    def _cleanup(self):
        try:
            if self._browser: self._browser.close()
        except Exception: pass
        try:
            if self._playwright: self._playwright.stop()
        except Exception: pass
        self._browser = None
        self._playwright = None

    def render(self, url: str) -> dict:
        result = {"url": url, "status": None, "html": "", "links": [],
                  "api_endpoints": [], "error": None}
        if not self._browser:
            result["error"] = "browser not started"
            return result

        context = None
        page = None
        api_calls = set()
        try:
            ctx_opts = {"ignore_https_errors": True}
            if self.user_agent:
                ctx_opts["user_agent"] = self.user_agent
            context = self._browser.new_context(**ctx_opts)
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

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()
