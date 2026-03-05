import argparse
import sys

from core.config import create_session, get_local_ip, resolve_target, Config
from core.requester import Requester
from core.parser import Parser
from core.crawler import Crawler
from core.engine import ScanEngine
from reporting.reporter import Reporter
from reporting.html_report import HTMLReport
from modules.xss.scanner import XSSScanner
from modules.reverse_shell.scanner import ReverseShellScanner
from modules.port_scanner.scanner import PortScanner
from modules.fuzzer.scanner import WebFuzzer
from exploitation.callback_server import CallbackServer, NullCallbackServer


def main(start_url, callback_ip=None, callback_port=None,
         no_callback=False, wordlist=None):

    # ==========================================
    # Configuracion inicial
    # ==========================================
    cb_host = callback_ip or get_local_ip()
    cb_port = callback_port or Config.CALLBACK_PORT

    session = create_session()
    requester = Requester(session)
    parser = Parser()
    reporter = Reporter()
    callback_server = None

    try:
        # ==========================================
        # FASE 1 - RECONOCIMIENTO
        # Resolucion DNS, info del objetivo, escaneo de puertos
        # ==========================================
        print("=" * 60)
        print("  FASE 1: RECONOCIMIENTO")
        print("=" * 60)

        # --- Resolucion DNS ---
        hostname, target_ip = resolve_target(start_url)
        print(f"[*] Objetivo:  {start_url}")
        print(f"[*] Hostname:  {hostname}")
        if target_ip:
            print(f"[*] IP:        {target_ip}")
        else:
            print(f"[!] No se pudo resolver la IP de {hostname}")

        if no_callback:
            print(f"[*] Callback:  desactivado")
        else:
            print(f"[*] Callback:  {cb_host}:{cb_port}")
        print()

        reporter.set_target_info(
            hostname=hostname,
            ip=target_ip,
            callback_ip=cb_host if not no_callback else None,
            callback_port=cb_port if not no_callback else None
        )

        # --- Escaneo de puertos ---
        port_scanner = PortScanner(reporter=reporter, timeout=2, max_workers=50)
        port_scanner.scan(start_url)

        # ==========================================
        # FASE 2 - PREPARACION
        # Fuzzing de directorios y archivos (superficie de ataque)
        # ==========================================
        print("=" * 60)
        print("  FASE 2: PREPARACION")
        print("=" * 60)

        fuzzer = WebFuzzer(
            requester=requester,
            reporter=reporter,
            max_workers=20,
            wordlist_file=wordlist
        )
        fuzzer.fuzz(start_url)

        # ==========================================
        # FASES 3-6 - DISTRIBUCION / EXPLOTACION / INSTALACION / C2
        # Crawling + escaneo de vulnerabilidades web
        # (XSS, Command Injection, Reverse Shell)
        # ==========================================
        print("=" * 60)
        print("  FASES 3-6: EXPLOTACION / INSTALACION / C2")
        print("=" * 60)

        # --- Callback server (opcional) ---
        if no_callback:
            callback_server = NullCallbackServer()
            print("[*] Callback server desactivado, deteccion OOB no disponible")
        else:
            callback_server = CallbackServer(host="0.0.0.0", port=cb_port)
            callback_server.start()
            print(f"[*] Callback server iniciado en 0.0.0.0:{cb_port}")

        crawler = Crawler(requester, parser, max_depth=2)

        # --- Modulos de escaneo web ---
        xss_scanner = XSSScanner(
            requester=requester,
            parser=parser,
            reporter=reporter,
            callback_server=callback_server,
            callback_host=cb_host,
            callback_port=cb_port
        )

        reverse_shell_scanner = ReverseShellScanner(
            requester=requester,
            parser=parser,
            reporter=reporter,
            callback_server=callback_server,
            callback_host=cb_host,
            callback_port=cb_port
        )

        scanners = [xss_scanner, reverse_shell_scanner]

        engine = ScanEngine(
            crawler=crawler,
            scanners=scanners,
            max_workers=5
        )

        engine.run(start_url)

    except KeyboardInterrupt:
        print("\n")
        print("=" * 60)
        print("  ESCANEO INTERRUMPIDO (Ctrl+C)")
        print("=" * 60)
        print("[!] Deteniendo escaneo...")
        print("[*] Guardando resultados parciales...")

    # ==========================================
    # REPORTES (se ejecuta siempre, incluso tras Ctrl+C)
    # ==========================================
    print("=" * 60)
    print("  GENERANDO REPORTES")
    print("=" * 60)

    reporter.save_json()
    HTMLReport.generate(reporter, output_file="scan_report.html")

    print()
    resumen = reporter.summary()
    total = resumen["total_vulnerabilities"]
    print(f"[*] Escaneo finalizado")
    print(f"[*] Total hallazgos: {total}")

    if resumen["by_phase"]:
        print(f"[*] Desglose por fase:")
        for phase in Config.PHASES:
            count = resumen["by_phase"].get(phase, 0)
            if count:
                print(f"      {phase}: {count}")

    if resumen["by_severity"]:
        print(f"[*] Desglose por severidad:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = resumen["by_severity"].get(sev, 0)
            if count:
                print(f"      {sev}: {count}")

    print()
    print(f"[*] Reporte JSON: report.json")
    print(f"[*] Reporte HTML: scan_report.html")

    if callback_server:
        callback_server.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ScannerV - Scanner de vulnerabilidades web (Cyber Kill Chain)"
    )
    parser.add_argument(
        "url",
        help="URL objetivo (ej: http://objetivo.com)"
    )
    parser.add_argument(
        "--callback-ip",
        default=None,
        help="IP del atacante para callbacks (default: auto-detectar)"
    )
    parser.add_argument(
        "--callback-port",
        type=int,
        default=None,
        help=f"Puerto del callback server (default: {Config.CALLBACK_PORT})"
    )
    parser.add_argument(
        "--no-callback",
        action="store_true",
        default=False,
        help="Desactivar el callback server (sin deteccion OOB)"
    )
    parser.add_argument(
        "--wordlist",
        default=None,
        help="Ruta a wordlist externa (.txt) para el fuzzer (una palabra por linea)"
    )

    args = parser.parse_args()
    main(
        args.url,
        callback_ip=args.callback_ip,
        callback_port=args.callback_port,
        no_callback=args.no_callback,
        wordlist=args.wordlist
    )
