import threading
from queue import Queue


class ScanEngine:

    def __init__(self, crawler, scanner, max_workers=5):
        self.crawler = crawler
        self.scanner = scanner
        self.max_workers = max_workers
        self.queue = Queue()
        self.threads = []

    # ----------------------------------------
    # Worker
    # ----------------------------------------

    def worker(self):

        while True:
            item = self.queue.get()

            if item is None:
                break

            url, html = item

            try:
                self.scanner.scan_page(url, html)
                self.scanner.check_stored_xss(url, html)
            except Exception as e:
                print(f"[Worker Error] {e}")

            self.queue.task_done()

    # ----------------------------------------
    # Run
    # ----------------------------------------

    def run(self, start_url):

        pages = self.crawler.crawl(start_url)

        # Crear workers
        for _ in range(self.max_workers):
            thread = threading.Thread(target=self.worker)
            thread.daemon = True
            thread.start()
            self.threads.append(thread)

        # Agregar tareas a la cola
        for page in pages:
            self.queue.put(page)

        # Esperar que termine
        self.queue.join()

        # Detener workers
        for _ in self.threads:
            self.queue.put(None)

        for thread in self.threads:
            thread.join()