import socket
import threading
import time
from queue import Queue
from urllib.parse import urlparse
from datetime import datetime, timezone

from modules.port_scanner.service_detector import ServiceDetector


class PortScanner:
    """
    Scanner de puertos TCP con identificacion de servicios.

    Funcionalidades:
    - TCP connect scan multi-hilo
    - Banner grabbing para fingerprinting de servicios
    - Identificacion de servicios por puerto y banner
    - Reporte de puertos abiertos con nivel de riesgo

    Este modulo se ejecuta como fase de reconocimiento independiente,
    NO se integra al engine de crawling (no implementa scan_page).
    """

    # Puertos mas comunes para escaneo rapido
    TOP_PORTS = [
        20, 21, 22, 23, 25, 53, 69, 80, 110, 111,
        119, 135, 137, 138, 139, 143, 161, 162, 389,
        443, 445, 465, 514, 515, 587, 631, 636, 993,
        995, 1080, 1433, 1434, 1521, 1723, 2049, 2181,
        3306, 3389, 5432, 5672, 5900, 5901, 6379, 6443,
        8000, 8080, 8443, 8888, 9090, 9200, 9300,
        11211, 27017, 27018, 50000,
    ]

    def __init__(self, reporter, timeout=2, max_workers=50):
        """
        Args:
            reporter: instancia de Reporter para guardar resultados
            timeout: timeout para conexion TCP (segundos)
            max_workers: hilos concurrentes para escaneo
        """
        self.reporter = reporter
        self.timeout = timeout
        self.max_workers = max_workers
        self.open_ports = []
        self.lock = threading.Lock()
        self._queue = Queue()

    # ----------------------------------------
    # Escaneo principal
    # ----------------------------------------

    def scan(self, target_url, ports=None):
        """
        Ejecuta el escaneo de puertos sobre el host del target_url.

        Args:
            target_url: URL objetivo (se extrae el hostname)
            ports: lista de puertos a escanear (default: TOP_PORTS)

        Returns:
            lista de dicts con info de puertos abiertos
        """
        host = self._extract_host(target_url)
        port_list = ports if ports else self.TOP_PORTS

        print(f"\n[Port Scanner] Iniciando escaneo de {host}")
        print(f"[Port Scanner] Puertos a escanear: {len(port_list)}")
        print(f"[Port Scanner] Workers: {self.max_workers} | "
              f"Timeout: {self.timeout}s")
        print("-" * 50)

        self.open_ports = []

        # Llenar la cola con puertos
        for port in port_list:
            self._queue.put((host, port))

        # Crear workers
        threads = []
        for _ in range(min(self.max_workers, len(port_list))):
            t = threading.Thread(target=self._worker)
            t.daemon = True
            t.start()
            threads.append(t)

        # Esperar a que terminen (interruptible por Ctrl+C)
        while self._queue.unfinished_tasks > 0:
            time.sleep(0.1)

        # Detener workers
        for _ in threads:
            self._queue.put(None)
        for t in threads:
            t.join()

        # Ordenar resultados por puerto
        self.open_ports.sort(key=lambda x: x["port"])

        # Resumen
        self._print_results(host)

        # Reportar al Reporter
        self._report_findings(host)

        return self.open_ports

    def scan_range(self, target_url, start_port=1, end_port=1024):
        """
        Escanea un rango completo de puertos.

        Args:
            target_url: URL objetivo
            start_port: puerto inicial (inclusive)
            end_port: puerto final (inclusive)
        """
        ports = list(range(start_port, end_port + 1))
        return self.scan(target_url, ports=ports)

    # ----------------------------------------
    # Worker y escaneo TCP
    # ----------------------------------------

    def _worker(self):
        """Worker que consume puertos de la cola y los escanea."""
        while True:
            item = self._queue.get()

            if item is None:
                self._queue.task_done()
                break

            host, port = item

            try:
                result = self._scan_port(host, port)
                if result:
                    with self.lock:
                        self.open_ports.append(result)
            except Exception as e:
                pass  # Silenciar errores individuales de puertos

            self._queue.task_done()

    def _scan_port(self, host, port):
        """
        Escanea un puerto individual via TCP connect.

        Returns:
            dict con info del puerto si esta abierto, None si cerrado
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            result = sock.connect_ex((host, port))

            if result == 0:
                # Puerto abierto - intentar banner grabbing
                banner = self._grab_banner(sock, host, port)

                # Identificar servicio
                service_info = ServiceDetector.identify(port, banner)

                print(f"  [OPEN] Puerto {port}/tcp - "
                      f"{service_info.get('service', 'Unknown')}"
                      f"{' (' + service_info.get('product', '') + ')' if service_info.get('product') else ''}"
                      f"{' v' + service_info.get('version', '') if service_info.get('version') else ''}")

                return {
                    "port": port,
                    "state": "open",
                    "service": service_info,
                    "banner": banner,
                }

            return None

        except (socket.timeout, ConnectionRefusedError, OSError):
            return None
        finally:
            sock.close()

    def _grab_banner(self, sock, host, port):
        """
        Intenta capturar el banner del servicio.
        Primero espera un banner espontaneo, luego intenta
        enviar probes HTTP/generico.
        """
        banner = None

        # Intento 1: leer banner espontaneo (SSH, FTP, SMTP, etc.)
        try:
            sock.settimeout(2)
            data = sock.recv(1024)
            if data:
                banner = data.decode("utf-8", errors="replace").strip()
                if banner:
                    return banner
        except (socket.timeout, OSError):
            pass

        # Intento 2: enviar probe HTTP para puertos web comunes
        http_ports = {80, 443, 8000, 8080, 8443, 8888, 9090}
        if port in http_ports or not banner:
            try:
                probe = f"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n"
                sock.sendall(probe.encode())
                sock.settimeout(2)
                data = sock.recv(1024)
                if data:
                    banner = data.decode("utf-8", errors="replace").strip()
                    if banner:
                        return banner
            except (socket.timeout, OSError, BrokenPipeError):
                pass

        # Intento 3: probe generico (newline)
        if not banner:
            try:
                new_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                new_sock.settimeout(2)
                new_sock.connect((host, port))
                new_sock.sendall(b"\r\n")
                data = new_sock.recv(1024)
                if data:
                    banner = data.decode("utf-8", errors="replace").strip()
                new_sock.close()
            except (socket.timeout, OSError):
                pass

        return banner

    # ----------------------------------------
    # Reporte y utilidades
    # ----------------------------------------

    def _report_findings(self, host):
        """Reporta los puertos abiertos al Reporter."""

        for port_info in self.open_ports:
            service = port_info["service"]
            port = port_info["port"]

            severity = ServiceDetector.get_risk_for_open_port(port, service)

            # Construir descripcion del servicio
            service_desc = service.get("service", "Unknown")
            if service.get("product"):
                service_desc += f" ({service['product']}"
                if service.get("version"):
                    service_desc += f" {service['version']}"
                service_desc += ")"

            exploit_data = {
                "port": port,
                "state": "open",
                "service_info": service,
                "banner": port_info.get("banner"),
                "host": host,
            }

            self.reporter.add_vulnerability(
                vuln_type="Open Port",
                url=f"{host}:{port}",
                parameter=f"port/{port}",
                payload=service_desc,
                severity=severity,
                phase="Reconocimiento",
                exploit_data=exploit_data
            )

    def _print_results(self, host):
        """Imprime un resumen de los resultados del escaneo."""

        print("-" * 50)
        print(f"[Port Scanner] Resultados para {host}")
        print(f"[Port Scanner] Puertos abiertos: {len(self.open_ports)}")
        print()

        if self.open_ports:
            print(f"  {'PUERTO':<10} {'ESTADO':<10} {'SERVICIO':<20} "
                  f"{'PRODUCTO':<25} {'RIESGO':<10}")
            print(f"  {'-'*10} {'-'*10} {'-'*20} {'-'*25} {'-'*10}")

            for p in self.open_ports:
                svc = p["service"]
                product = svc.get("product", "")
                if svc.get("version"):
                    product += f" {svc['version']}"

                print(f"  {p['port']:<10} {'open':<10} "
                      f"{svc.get('service', 'Unknown'):<20} "
                      f"{product:<25} "
                      f"{svc.get('risk', 'INFO'):<10}")

        print()

    @staticmethod
    def _extract_host(url):
        """Extrae el hostname de una URL."""
        parsed = urlparse(url)

        if parsed.hostname:
            return parsed.hostname

        # Si no tiene esquema, intentar agregar uno
        if "://" not in url:
            parsed = urlparse(f"http://{url}")
            if parsed.hostname:
                return parsed.hostname

        # Ultimo recurso: limpiar manualmente
        host = url.split("://")[-1].split("/")[0].split(":")[0]
        return host
