import requests
import urllib3
import random

from utils.logger import Logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WebRequester:

    def __init__(self, timeout=5):
        self.timeout = timeout
        self.session = requests.Session()

        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (X11; Linux x86_64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        ]

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
                "length": len(response.text)
            }

        except requests.exceptions.RequestException:
            # 🔥 HANDLE SEMUA ERROR SEKALIGUS (timeout, conn, dll)
            return None

        except Exception:
            return None
