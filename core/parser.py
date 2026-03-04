from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class Parser:

    @staticmethod
    def extract_forms(html, base_url):
        forms = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            for form in soup.find_all("form"):
                action = form.get("action", base_url)
                action = urljoin(base_url, action)

                method = form.get("method", "get").lower()

                inputs = {}
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name:
                        inputs[name] = inp.get("value", "")

                forms.append({
                    "action": action,
                    "method": method,
                    "inputs": inputs
                })
        except Exception:
            pass

        return forms

    @staticmethod
    def extract_links_with_params(html, base_url):
        links = set()
        try:
            soup = BeautifulSoup(html, "html.parser")
            base_domain = urlparse(base_url).netloc

            for tag in soup.find_all("a", href=True):
                href = urljoin(base_url, tag["href"])
                if base_domain in href and "?" in href:
                    links.add(href)

        except Exception:
            pass

        return list(links)

    @staticmethod
    def extract_internal_links(html, base_url):
        links = set()
        try:
            soup = BeautifulSoup(html, "html.parser")
            base_domain = urlparse(base_url).netloc

            for tag in soup.find_all("a", href=True):
                href = urljoin(base_url, tag["href"])
                if base_domain in href:
                    links.add(href)

        except Exception:
            pass

        return list(links)

    @staticmethod
    def get_title(html):
        try:
            soup = BeautifulSoup(html, "html.parser")
            t = soup.find("title")
            return t.get_text().strip()[:80] if t else ""
        except Exception:
            return ""