import requests
import urllib3
import random

from utils.logger import Logger

# 🔥 Disable SSL warning (biar gak spam)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WebRequester:

    def __init__(self, timeout=5):

        self.timeout = timeout

        self.session = requests.Session()

        # 🔥 Random User-Agent (basic evasion)
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (X11; Linux x86_64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"
        ]

    # =========================
    # 🔹 GET REQUEST
    # =========================
    def request(self, url):

        try:
            headers = {
                "User-Agent": random.choice(self.user_agents)
            }

            response = self.session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False
            )

            return {
                "url": url,
                "status_code": response.status_code,
                "length": len(response.text),
                "headers": dict(response.headers)
            }

        except requests.exceptions.Timeout:
            Logger.debug(f"Timeout: {url}")
            return None

        except requests.exceptions.ConnectionError:
            Logger.debug(f"Connection error: {url}")
            return None

        except Exception as e:
            Logger.debug(f"Request error ({url}): {e}")
            return None
