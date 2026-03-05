import threading
import time
from queue import Queue
from urllib.parse import urljoin

from modules.fuzzer.wordlist import Wordlist


class WebFuzzer:
    """
    Fuzzer de directorios y archivos estilo ffuf.

    Descubre rutas ocultas, archivos sensibles y directorios
    expuestos en el servidor web objetivo.

    Fase del Kill Chain: Preparacion (reconocimiento activo
    de superficie de ataque).
    """

    # Codigos de respuesta que indican hallazgo
    VALID_STATUS = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405}

    # Codigos que indican contenido sensible expuesto
    SENSITIVE_STATUS = {200, 201, 202, 204}

    # Rutas conocidas como sensibles
    SENSITIVE_PATHS = {
        ".env", ".git/config", ".git/HEAD", ".svn/entries",
        ".htpasswd", "wp-config.php", "config.php", "database.yml",
        "phpinfo.php", "info.php", "backup.sql", "dump.sql",
        "id_rsa", ".ssh/id_rsa", "server-status", "server-info",
        "elmah.axd", "trace.axd", "web.config",
    }

    def __init__(self, requester, reporter, max_workers=20,
                 wordlist_file=None, extensions=False):
        """
        Args:
            requester: instancia de Requester
            reporter: instancia de Reporter
            max_workers: hilos concurrentes
            wordlist_file: ruta a wordlist externa (opcional)
            extensions: si True, prueba con multiples extensiones
        """
        self.requester = requester
        self.reporter = reporter
        self.max_workers = max_workers
        self.wordlist_file = wordlist_file
        self.use_extensions = extensions
        self.results = []
        self.lock = threading.Lock()
        self._queue = Queue()
        self._scanned = 0
        self._total = 0

    # ----------------------------------------
    # Fuzzing principal
    # ----------------------------------------

    def fuzz(self, target_url):
        """
        Ejecuta el fuzzing de directorios/archivos sobre la URL objetivo.

        Args:
            target_url: URL base del objetivo

        Returns:
            lista de dicts con los hallazgos
        """
        # Asegurar que la URL base termina en /
        base_url = target_url.rstrip("/") + "/"

        # Cargar wordlist
        if self.wordlist_file:
            words = Wordlist.load_from_file(self.wordlist_file)
        elif self.use_extensions:
            words = Wordlist.get_with_extensions()
        else:
            words = Wordlist.get_default()

        self._total = len(words)
        self._scanned = 0
        self.results = []

        print(f"\n[Fuzzer] Iniciando fuzzing en {base_url}")
        print(f"[Fuzzer] Palabras a probar: {self._total}")
        print(f"[Fuzzer] Workers: {self.max_workers}")
        print("-" * 50)

        # Llenar cola
        for word in words:
            full_url = urljoin(base_url, word)
            self._queue.put((full_url, word))

        # Crear workers
        threads = []
        for _ in range(min(self.max_workers, self._total)):
            t = threading.Thread(target=self._worker)
            t.daemon = True
            t.start()
            threads.append(t)

        # Esperar (interruptible por Ctrl+C)
        while self._queue.unfinished_tasks > 0:
            time.sleep(0.1)

        # Detener workers
        for _ in threads:
            self._queue.put(None)
        for t in threads:
            t.join()

        # Ordenar por status code
        self.results.sort(key=lambda x: (x["status"], x["path"]))

        # Imprimir resultados
        self._print_results(base_url)

        # Reportar hallazgos
        self._report_findings(base_url)

        return self.results

    # ----------------------------------------
    # Worker
    # ----------------------------------------

    def _worker(self):
        while True:
            item = self._queue.get()

            if item is None:
                self._queue.task_done()
                break

            url, word = item

            try:
                self._test_path(url, word)
            except Exception:
                pass

            with self.lock:
                self._scanned += 1

            self._queue.task_done()

    def _test_path(self, url, word):
        """Prueba una ruta individual."""

        response = self.requester.get(url)

        if not response:
            return

        status = response.status_code
        length = len(response.content)

        if status in self.VALID_STATUS:
            # Determinar si es sensible
            is_sensitive = (
                word in self.SENSITIVE_PATHS or
                any(word.endswith(ext) for ext in
                    [".env", ".sql", ".bak", ".old", ".log",
                     ".config", ".yml", ".yaml", ".json"])
            )

            # Determinar titulo de la pagina
            title = ""
            if "text/html" in response.headers.get("content-type", ""):
                try:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(response.text[:2000], "html.parser")
                    t = soup.find("title")
                    title = t.get_text().strip()[:60] if t else ""
                except Exception:
                    pass

            result = {
                "path": word,
                "url": url,
                "status": status,
                "length": length,
                "title": title,
                "sensitive": is_sensitive,
                "redirect": response.headers.get("Location", "") if status in {301, 302, 307, 308} else "",
            }

            with self.lock:
                self.results.append(result)

            # Imprimir hallazgo en tiempo real
            status_label = self._status_label(status)
            sensitive_mark = " [SENSITIVE]" if is_sensitive else ""
            print(f"  [{status}] {status_label} /{word:<40} "
                  f"[{length} bytes]{sensitive_mark}")

    # ----------------------------------------
    # Reporte
    # ----------------------------------------

    def _report_findings(self, base_url):
        """Reporta los hallazgos al Reporter."""

        for result in self.results:
            # Determinar severidad
            severity = self._assess_severity(result)

            exploit_data = {
                "status_code": result["status"],
                "content_length": result["length"],
                "title": result["title"],
                "redirect": result["redirect"],
                "sensitive": result["sensitive"],
            }

            self.reporter.add_vulnerability(
                vuln_type="Directory/File Found",
                url=result["url"],
                parameter=f"/{result['path']}",
                payload=f"HTTP {result['status']} | {result['length']} bytes",
                severity=severity,
                phase="Preparacion",
                exploit_data=exploit_data
            )

    def _assess_severity(self, result):
        """Evalua la severidad de un hallazgo."""

        path = result["path"]
        status = result["status"]

        # Archivos sensibles con contenido accesible
        if result["sensitive"] and status in self.SENSITIVE_STATUS:
            return "CRITICAL"

        # Paneles de administracion accesibles
        admin_paths = {"admin", "administrator", "dashboard", "cpanel",
                       "phpmyadmin", "adminer", "console", "panel"}
        if any(path.startswith(ap) for ap in admin_paths) and status == 200:
            return "HIGH"

        # Info de configuracion/debug
        info_paths = {"phpinfo", "info.php", "server-status", "server-info",
                      "debug", "swagger", "api-docs", "graphiql"}
        if any(path.startswith(ip) for ip in info_paths) and status == 200:
            return "HIGH"

        # Git/SVN expuesto
        if path.startswith((".git", ".svn")) and status == 200:
            return "CRITICAL"

        # 403 Forbidden (existe pero no accesible)
        if status == 403:
            return "LOW"

        # 401 Unauthorized (requiere auth)
        if status == 401:
            return "MEDIUM"

        # Redirects
        if status in {301, 302, 307, 308}:
            return "LOW"

        # Default
        if status == 200:
            return "MEDIUM"

        return "LOW"

    # ----------------------------------------
    # Impresion
    # ----------------------------------------

    def _print_results(self, base_url):
        """Imprime resumen de resultados."""

        print("-" * 50)
        print(f"[Fuzzer] Resultados para {base_url}")
        print(f"[Fuzzer] Rutas probadas: {self._total}")
        print(f"[Fuzzer] Hallazgos: {len(self.results)}")
        print()

        if self.results:
            sensitive = [r for r in self.results if r["sensitive"]]
            accessible = [r for r in self.results
                          if r["status"] in self.SENSITIVE_STATUS]
            forbidden = [r for r in self.results if r["status"] == 403]

            print(f"  Accesibles (2xx): {len(accessible)}")
            print(f"  Prohibidos (403): {len(forbidden)}")
            print(f"  Sensibles:        {len(sensitive)}")
        print()

    @staticmethod
    def _status_label(code):
        """Etiqueta legible para el status code."""
        labels = {
            200: "OK", 201: "Created", 204: "No Content",
            301: "Moved", 302: "Found", 307: "Redirect", 308: "Permanent",
            401: "Unauthorized", 403: "Forbidden", 405: "Not Allowed",
        }
        return labels.get(code, str(code))
