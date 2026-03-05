import threading
import time
from queue import Queue


class ScanEngine:

    def __init__(self, crawler, scanners, max_workers=5):
        self.crawler = crawler
        # Soportar un solo scanner o una lista de scanners
        if isinstance(scanners, list):
            self.scanners = scanners
        else:
            self.scanners = [scanners]
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

            for scanner in self.scanners:
                try:
                    scanner.scan_page(url, html)

                    # Ejecutar post_scan si el scanner lo implementa
                    if hasattr(scanner, "post_scan"):
                        scanner.post_scan(url, html)
                except Exception as e:
                    print(f"[Worker Error] [{scanner.__class__.__name__}] {e}")

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

        # Esperar que termine (interruptible por Ctrl+C)
        while self.queue.unfinished_tasks > 0:
            time.sleep(0.1)

        # Detener workers
        for _ in self.threads:
            self.queue.put(None)

        for thread in self.threads:
            thread.join()