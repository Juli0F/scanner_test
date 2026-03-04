from core.injector import Injector
from modules.xss.payloads import PayloadFactory
from modules.xss.detector import XSSDetector
from modules.xss.stored_manager import StoredXSSManager


class XSSScanner:

    def __init__(self, requester, parser, reporter, callback_server):
        self.requester = requester
        self.parser = parser
        self.reporter = reporter
        self.callback_server = callback_server
        self.stored_manager = StoredXSSManager()

    def scan_page(self, url, html):

        # Generar múltiples payloads
        payloads = PayloadFactory.generate_multiple(
            callback_host="127.0.0.1",
            callback_port=8000
        )

        # Escanear URLs
        self._scan_links(url, html, payloads)

        # Escanear formularios
        self._scan_forms(url, html, payloads)

    # ----------------------------------------
    # LINKS
    # ----------------------------------------
    def check_stored_xss(self, url, html):

        pending = self.stored_manager.get_pending()

        for token, data in pending.items():

            if token in html:
                confirmed = self.callback_server.is_confirmed(token)

                severity = "CRITICAL" if confirmed else "HIGH"

                self.reporter.add_vulnerability(
                    vuln_type="XSS Stored",
                    url=url,
                    parameter=data["parameter"],
                    payload=data["payload"],
                    severity=severity
                )

                self.stored_manager.mark_confirmed(token)
    def _scan_links(self, base_url, html, payloads):

        links = self.parser.extract_links_with_params(html, base_url)

        for link in links:
            for token, payload in payloads:

                injections = Injector.inject_in_url(link, payload)

                for injected_url, param in injections:

                    response = self.requester.get(injected_url)

                    if not response:
                        continue

                    reflected = XSSDetector.detect_reflection(
                        response.text, token
                    )

                    if reflected:
                        self._confirm_and_report(
                            injected_url,
                            param,
                            payload,
                            token,
                            "XSS Reflected"
                        )

    # ----------------------------------------
    # FORMS
    # ----------------------------------------
    def _scan_forms(self, base_url, html, payloads):

        forms = self.parser.extract_forms(html, base_url)

        for form in forms:
            for token, payload in payloads:

                injections = Injector.inject_in_form(form, payload)

                for injected_form in injections:

                    if injected_form["method"] == "post":
                        response = self.requester.post(
                            injected_form["action"],
                            data=injected_form["inputs"]
                        )
                    else:
                        response = self.requester.get(
                            injected_form["action"],
                            params=injected_form["inputs"]
                        )

                    if response and response.status_code < 500:

                        # Registrar como posible Stored XSS
                        self.stored_manager.register_token(
                            token=token,
                            payload=payload,
                            origin_url=injected_form["action"],
                            parameter=injected_form["injected_param"]
                        )

                        # Luego verificar si es reflected
                        reflected = XSSDetector.detect_reflection(
                            response.text,
                            token
                        )

                        if reflected:
                            self._confirm_and_report(
                                injected_form["action"],
                                injected_form["injected_param"],
                                payload,
                                token,
                                "XSS Reflected"
                            )
    # ----------------------------------------
    # Confirmacion y reporte
    # ----------------------------------------

    def _confirm_and_report(self, url, param, payload, token, vuln_type):

        confirmed = self.callback_server.is_confirmed(token)

        severity = "CRITICAL" if confirmed else "HIGH"

        exploit_data = self.callback_server.get_exploit_data(token)

        self.reporter.add_vulnerability(
            vuln_type=vuln_type,
            url=url,
            parameter=param,
            payload=payload,
            severity=severity,
            exploit_data=exploit_data
        )