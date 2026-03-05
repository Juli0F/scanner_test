import time

from core.injector import Injector
from modules.reverse_shell.payloads import ReverseShellPayloadFactory
from modules.reverse_shell.detector import ReverseShellDetector


class ReverseShellScanner:
    """
    Scanner de vulnerabilidades de inyeccion de comandos / reverse shell.

    Estrategias de deteccion:
    1. Time-based: inyecta comandos sleep/ping y mide el tiempo de respuesta
    2. Callback-based: inyecta curl/wget al callback server y verifica conexion
    3. Error-based: busca output de comandos en la respuesta
    4. Reverse shell indicators: prueba payloads tipicos de reverse shell
       que generan callbacks detectables
    """

    # Delay para payloads time-based (segundos)
    TIME_DELAY = 5

    def __init__(self, requester, parser, reporter, callback_server,
                 callback_host="127.0.0.1", callback_port=8000):
        self.requester = requester
        self.parser = parser
        self.reporter = reporter
        self.callback_server = callback_server
        self.callback_host = callback_host
        self.callback_port = callback_port

    # ----------------------------------------
    # Interface publica (requerida por engine)
    # ----------------------------------------

    def scan_page(self, url, html):
        """Escanea una pagina buscando inyeccion de comandos."""

        # Fase 1: Payloads error-based (rapidos, no requieren espera)
        self._scan_error_based(url, html)

        # Fase 2: Payloads callback-based (detectables via OOB)
        self._scan_callback_based(url, html)

        # Fase 3: Payloads de reverse shell indicators (callback)
        self._scan_reverse_shell_indicators(url, html)

        # Fase 4: Payloads time-based (lentos, se ejecutan al final)
        self._scan_time_based(url, html)

    # ----------------------------------------
    # Error-based scanning
    # ----------------------------------------

    def _scan_error_based(self, url, html):
        """Inyecta comandos y busca output reconocible en la respuesta."""

        payloads = ReverseShellPayloadFactory.generate_error_based()

        # Escanear parametros en URLs
        links = self.parser.extract_links_with_params(html, url)
        for link in links:
            for payload_data in payloads:
                token, payload, ptype, cmd, pattern = payload_data
                self._test_error_payload_on_url(link, token, payload, cmd, pattern)

        # Escanear formularios
        forms = self.parser.extract_forms(html, url)
        for form in forms:
            for payload_data in payloads:
                token, payload, ptype, cmd, pattern = payload_data
                self._test_error_payload_on_form(form, token, payload, cmd, pattern)

    def _test_error_payload_on_url(self, url, token, payload, cmd, pattern):
        """Prueba un payload error-based en parametros de URL."""

        injections = Injector.inject_in_url(url, payload)

        for injected_url, param in injections:
            response = self.requester.get(injected_url)

            if not response:
                continue

            # Verificar reflection del token
            detection = ReverseShellDetector.detect_token_reflection(
                response.text, token
            )

            # Verificar patrones de error/output
            if not detection:
                detection = ReverseShellDetector.detect_error_based(
                    response.text, pattern
                )

            if detection:
                self._report_vulnerability(
                    url=injected_url,
                    parameter=param,
                    payload=payload,
                    token=token,
                    detection=detection,
                    vuln_type="Command Injection"
                )
                return  # Evitar duplicados en el mismo parametro

    def _test_error_payload_on_form(self, form, token, payload, cmd, pattern):
        """Prueba un payload error-based en campos de formulario."""

        injections = Injector.inject_in_form(form, payload)

        for injected_form in injections:
            response = self._send_form(injected_form)

            if not response:
                continue

            detection = ReverseShellDetector.detect_token_reflection(
                response.text, token
            )

            if not detection:
                detection = ReverseShellDetector.detect_error_based(
                    response.text, pattern
                )

            if detection:
                self._report_vulnerability(
                    url=injected_form["action"],
                    parameter=injected_form["injected_param"],
                    payload=payload,
                    token=token,
                    detection=detection,
                    vuln_type="Command Injection"
                )
                return

    # ----------------------------------------
    # Callback-based scanning
    # ----------------------------------------

    def _scan_callback_based(self, url, html):
        """Inyecta payloads que contactan al callback server."""

        payloads = ReverseShellPayloadFactory.generate_callback_based(
            self.callback_host, self.callback_port
        )

        links = self.parser.extract_links_with_params(html, url)
        for link in links:
            for token, payload, ptype in payloads:
                self._test_callback_payload_on_url(link, token, payload)

        forms = self.parser.extract_forms(html, url)
        for form in forms:
            for token, payload, ptype in payloads:
                self._test_callback_payload_on_form(form, token, payload)

    def _test_callback_payload_on_url(self, url, token, payload):
        """Prueba un payload callback-based en parametros de URL."""

        injections = Injector.inject_in_url(url, payload)

        for injected_url, param in injections:
            response = self.requester.get(injected_url)

            if not response:
                continue

            # Esperar breve para que el callback llegue
            time.sleep(1)

            detection = ReverseShellDetector.detect_callback(
                self.callback_server, token
            )

            if detection:
                self._report_vulnerability(
                    url=injected_url,
                    parameter=param,
                    payload=payload,
                    token=token,
                    detection=detection,
                    vuln_type="Reverse Shell (OOB)"
                )
                return

    def _test_callback_payload_on_form(self, form, token, payload):
        """Prueba un payload callback-based en campos de formulario."""

        injections = Injector.inject_in_form(form, payload)

        for injected_form in injections:
            response = self._send_form(injected_form)

            if not response:
                continue

            time.sleep(1)

            detection = ReverseShellDetector.detect_callback(
                self.callback_server, token
            )

            if detection:
                self._report_vulnerability(
                    url=injected_form["action"],
                    parameter=injected_form["injected_param"],
                    payload=payload,
                    token=token,
                    detection=detection,
                    vuln_type="Reverse Shell (OOB)"
                )
                return

    # ----------------------------------------
    # Reverse shell indicators
    # ----------------------------------------

    def _scan_reverse_shell_indicators(self, url, html):
        """Inyecta payloads tipicos de reverse shell y detecta via callback."""

        payloads = ReverseShellPayloadFactory.generate_reverse_shell_indicators(
            self.callback_host, self.callback_port
        )

        links = self.parser.extract_links_with_params(html, url)
        for link in links:
            for token, payload, ptype in payloads:
                self._test_callback_payload_on_url(link, token, payload)

        forms = self.parser.extract_forms(html, url)
        for form in forms:
            for token, payload, ptype in payloads:
                self._test_callback_payload_on_form(form, token, payload)

    # ----------------------------------------
    # Time-based scanning
    # ----------------------------------------

    def _scan_time_based(self, url, html):
        """Inyecta payloads basados en tiempo y mide la respuesta."""

        payloads = ReverseShellPayloadFactory.generate_time_based(
            delay=self.TIME_DELAY
        )

        links = self.parser.extract_links_with_params(html, url)
        for link in links:
            for token, payload, ptype in payloads:
                self._test_time_payload_on_url(link, token, payload)

        forms = self.parser.extract_forms(html, url)
        for form in forms:
            for token, payload, ptype in payloads:
                self._test_time_payload_on_form(form, token, payload)

    def _test_time_payload_on_url(self, url, token, payload):
        """Prueba un payload time-based en parametros de URL."""

        injections = Injector.inject_in_url(url, payload)

        for injected_url, param in injections:
            start = time.time()
            response = self.requester.get(injected_url)
            end = time.time()

            if not response:
                continue

            detection = ReverseShellDetector.detect_time_based(
                start, end, self.TIME_DELAY
            )

            if detection:
                self._report_vulnerability(
                    url=injected_url,
                    parameter=param,
                    payload=payload,
                    token=token,
                    detection=detection,
                    vuln_type="Command Injection (Time-based)"
                )
                return

    def _test_time_payload_on_form(self, form, token, payload):
        """Prueba un payload time-based en campos de formulario."""

        injections = Injector.inject_in_form(form, payload)

        for injected_form in injections:
            start = time.time()
            response = self._send_form(injected_form)
            end = time.time()

            if not response:
                continue

            detection = ReverseShellDetector.detect_time_based(
                start, end, self.TIME_DELAY
            )

            if detection:
                self._report_vulnerability(
                    url=injected_form["action"],
                    parameter=injected_form["injected_param"],
                    payload=payload,
                    token=token,
                    detection=detection,
                    vuln_type="Command Injection (Time-based)"
                )
                return

    # ----------------------------------------
    # Utilidades
    # ----------------------------------------

    def _send_form(self, injected_form):
        """Envia un formulario inyectado (POST o GET)."""

        if injected_form["method"] == "post":
            return self.requester.post(
                injected_form["action"],
                data=injected_form["inputs"]
            )
        else:
            return self.requester.get(
                injected_form["action"],
                params=injected_form["inputs"]
            )

    def _report_vulnerability(self, url, parameter, payload, token,
                              detection, vuln_type):
        """Reporta una vulnerabilidad encontrada."""

        # Determinar severidad segun el metodo de deteccion
        confidence = detection.get("confidence", "MEDIUM")
        severity_map = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
        }
        severity = severity_map.get(confidence, "MEDIUM")

        # Si hay confirmacion por callback, siempre es CRITICAL
        if detection.get("method") == "callback":
            severity = "CRITICAL"

        # Determinar fase del kill chain segun tipo de vuln y deteccion
        if detection.get("method") == "callback" and "Reverse Shell" in vuln_type:
            phase = "Comando y Control"
        elif "Reverse Shell" in vuln_type:
            phase = "Instalacion"
        else:
            phase = "Explotacion"

        exploit_data = {
            "detection_method": detection.get("method"),
            "detection_details": detection,
            "token": token,
        }

        self.reporter.add_vulnerability(
            vuln_type=vuln_type,
            url=url,
            parameter=parameter,
            payload=payload,
            severity=severity,
            phase=phase,
            exploit_data=exploit_data
        )

        print(f"[!] {vuln_type} encontrado: {url} | param={parameter} | "
              f"metodo={detection.get('method')} | severidad={severity}")
