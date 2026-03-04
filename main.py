import sys

from core.config import create_session
from core.requester import Requester
from core.parser import Parser
from core.crawler import Crawler
from core.engine import ScanEngine
from reporting.reporter import Reporter
from reporting.html_report import HTMLReport
from modules.xss.scanner import XSSScanner
from exploitation.callback_server import CallbackServer


def main(start_url):

    session = create_session()
    requester = Requester(session)
    parser = Parser()
    reporter = Reporter()

    callback_server = CallbackServer(host="0.0.0.0", port=8000)
    callback_server.start()

    crawler = Crawler(requester, parser, max_depth=2)

    scanner = XSSScanner(
        requester,
        parser,
        reporter,
        callback_server
    )


    engine = ScanEngine(
        crawler=crawler,
        scanner=scanner,
        max_workers=5
    )

    engine.run(start_url)
    reporter.save_json()
    HTMLReport.generate(
        reporter.vulnerabilities,
        output_file="scan_report.html"
    )

    print("Escaneo finalizado")
    resumen = reporter.summary()
    print(f"Vulnerabilidades encontradas: {resumen['total_vulnerabilities']}")

    callback_server.stop()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python main.py http://objetivo.com")
    else:
        main(sys.argv[1])