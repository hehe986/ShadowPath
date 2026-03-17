import requests
from utils.logger import Logger


class WebRequester:

    def __init__(self, timeout=5):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "ShadowPath/1.0 (Active Scanner)"
        })

    def request(self, url):
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False
            )

            return {
                "url": url,
                "status_code": response.status_code,
                "length": len(response.text)
            }

        except requests.exceptions.Timeout:
            return None

        except requests.exceptions.ConnectionError:
            return None

        except Exception as e:
            Logger.debug(f"Request error: {e}")
            return None
