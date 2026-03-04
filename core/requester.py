# core/requester.py

import time
import logging
import requests
from .config import Config


class Requester:

    def __init__(self, session, proxy=None, verify_ssl=True):
        self.session = session
        self.verify_ssl = verify_ssl

        if proxy:
            self.session.proxies.update({
                "http": proxy,
                "https": proxy
            })

        # Logger profesional
        self.logger = logging.getLogger("Requester")
        self.logger.setLevel(logging.INFO)

    def request(self, method, url, **kwargs):
        """
        Método centralizado para todas las peticiones HTTP.
        """

        for attempt in range(Config.MAX_RETRIES):
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    timeout=Config.TIMEOUT,
                    allow_redirects=True,
                    verify=self.verify_ssl,
                    **kwargs
                )

                # Manejo Rate Limit
                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After")

                    if retry_after and retry_after.isdigit():
                        sleep_time = int(retry_after)
                    else:
                        sleep_time = Config.BASE_DELAY * (2 ** attempt)

                    self.logger.warning(
                        f"[429] Rate limit en {url} - Esperando {sleep_time}s"
                    )
                    time.sleep(sleep_time)
                    continue

                # Manejo errores 5xx con retry
                if 500 <= response.status_code < 600:
                    sleep_time = Config.BASE_DELAY * (2 ** attempt)
                    self.logger.warning(
                        f"[{response.status_code}] Error servidor en {url}, retry..."
                    )
                    time.sleep(sleep_time)
                    continue

                time.sleep(Config.DELAY)
                return response

            except requests.exceptions.Timeout:
                self.logger.warning(f"[Timeout] {url}")
            except requests.exceptions.ConnectionError:
                self.logger.warning(f"[ConnectionError] {url}")
            except requests.exceptions.RequestException as e:
                self.logger.error(f"[RequestException] {url} -> {e}")
                break

        self.logger.error(f"[FAIL] No se pudo acceder a {url}")
        return None

    # Métodos auxiliares

    def get(self, url, params=None, headers=None):
        return self.request("GET", url, params=params, headers=headers)

    def post(self, url, data=None, json=None, headers=None):
        return self.request("POST", url, data=data, json=json, headers=headers)

    def get_cookies(self):
        return self.session.cookies

    def set_cookie(self, key, value):
        self.session.cookies.set(key, value)