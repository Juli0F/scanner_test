# core/crawler.py

from collections import deque
from urllib.parse import urlparse, urljoin, urldefrag
import logging


class Crawler:

    IGNORED_EXTENSIONS = (
        ".jpg", ".jpeg", ".png", ".gif",
        ".css", ".js", ".svg",
        ".ico", ".woff", ".woff2",
        ".ttf", ".eot", ".pdf",
        ".zip", ".rar", ".tar", ".gz"
    )

    LOGOUT_KEYWORDS = ("logout", "signout", "exit")

    def __init__(self, requester, parser, max_depth=2):
        self.requester = requester
        self.parser = parser
        self.max_depth = max_depth
        self.visited = set()
        self.logger = logging.getLogger("Crawler")

    def normalize_url(self, url):
        url, _ = urldefrag(url)  # eliminar #fragment
        return url.rstrip("/")

    def is_valid_url(self, base_domain, url):
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False

        if base_domain not in parsed.netloc:
            return False

        if any(parsed.path.lower().endswith(ext) for ext in self.IGNORED_EXTENSIONS):
            return False

        if any(keyword in parsed.path.lower() for keyword in self.LOGOUT_KEYWORDS):
            return False

        return True

    def crawl(self, start_url):
        queue = deque([(start_url, 0)])
        base_domain = urlparse(start_url).netloc
        discovered_pages = []

        while queue:
            current_url, depth = queue.popleft()

            normalized_url = self.normalize_url(current_url)

            if normalized_url in self.visited:
                continue

            if depth > self.max_depth:
                continue

            self.visited.add(normalized_url)

            response = self.requester.get(normalized_url)
            if not response:
                continue

            html = response.text
            discovered_pages.append((normalized_url, html))

            links = self.parser.extract_internal_links(html, normalized_url)

            for link in links:
                normalized_link = self.normalize_url(link)

                if (
                    normalized_link not in self.visited
                    and self.is_valid_url(base_domain, normalized_link)
                ):
                    queue.append((normalized_link, depth + 1))

        return discovered_pages