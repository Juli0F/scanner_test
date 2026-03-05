import re
import time


class ReverseShellDetector:
    """
    Detecta evidencia de inyeccion de comandos / reverse shell
    mediante tres estrategias:
    - Time-based: mide si la respuesta tardo mas de lo esperado
    - Error-based: busca patrones reconocibles en la respuesta
    - Callback-based: verifica si el callback server recibio conexion
    """

    # Patrones que indican ejecucion de comandos en la respuesta
    ERROR_PATTERNS = [
        r"uid=\d+\(\w+\)",                    # Linux id output
        r"root:.*:0:0:",                       # /etc/passwd
        r"\[fonts\]",                          # win.ini
        r"Microsoft Windows \[Version",        # Windows ver
        r"Linux\s+\S+\s+\d+\.\d+",           # uname -a
        r"Darwin\s+\S+\s+\d+\.\d+",          # macOS uname
        r"(sh|bash|cmd):\s+.*not found",       # Command not found (indica shell)
        r"syntax error near unexpected token", # Bash syntax error
        r"The syntax of the command is incorrect",  # Windows cmd error
        r"is not recognized as an internal",   # Windows cmd not found
        r"No such file or directory",          # Linux file not found
        r"/bin/(sh|bash|zsh|csh)",             # Shell paths en output
    ]

    # Patrones compilados para mejor rendimiento
    _compiled_patterns = [re.compile(p, re.IGNORECASE) for p in ERROR_PATTERNS]

    @classmethod
    def detect_time_based(cls, start_time, end_time, expected_delay=5, tolerance=2):
        """
        Detecta inyeccion time-based comparando el tiempo de respuesta
        con el delay esperado.

        Args:
            start_time: timestamp antes de enviar la peticion
            end_time: timestamp despues de recibir la respuesta
            expected_delay: delay inyectado en el payload (segundos)
            tolerance: margen de tolerancia (segundos)

        Returns:
            dict con resultado o None si no se detecto
        """
        elapsed = end_time - start_time

        if elapsed >= (expected_delay - tolerance):
            return {
                "method": "time_based",
                "elapsed_seconds": round(elapsed, 2),
                "expected_delay": expected_delay,
                "confidence": "HIGH" if elapsed >= expected_delay else "MEDIUM"
            }

        return None

    @classmethod
    def detect_error_based(cls, response_text, custom_pattern=None):
        """
        Busca patrones reconocibles en la respuesta que indiquen
        que un comando fue ejecutado.

        Args:
            response_text: HTML/texto de la respuesta
            custom_pattern: patron regex adicional para buscar

        Returns:
            dict con resultado o None si no se detecto
        """
        if not response_text:
            return None

        # Buscar patrones genericos
        for pattern in cls._compiled_patterns:
            match = pattern.search(response_text)
            if match:
                return {
                    "method": "error_based",
                    "matched_pattern": pattern.pattern,
                    "matched_text": match.group()[:100],
                    "confidence": "HIGH"
                }

        # Buscar patron personalizado (del payload)
        if custom_pattern:
            try:
                custom_re = re.compile(custom_pattern, re.IGNORECASE)
                match = custom_re.search(response_text)
                if match:
                    return {
                        "method": "error_based",
                        "matched_pattern": custom_pattern,
                        "matched_text": match.group()[:100],
                        "confidence": "HIGH"
                    }
            except re.error:
                pass

        return None

    @classmethod
    def detect_token_reflection(cls, response_text, token):
        """
        Detecta si un token inyectado via 'echo TOKEN' aparece
        en la respuesta.

        Returns:
            dict con resultado o None
        """
        if not response_text or not token:
            return None

        if token in response_text:
            return {
                "method": "token_reflection",
                "token": token,
                "confidence": "HIGH"
            }

        return None

    @classmethod
    def detect_callback(cls, callback_server, token):
        """
        Verifica si el callback server recibio una conexion
        con el token inyectado.

        Returns:
            dict con resultado o None
        """
        if callback_server and callback_server.is_confirmed(token):
            exploit_data = callback_server.get_exploit_data(token)
            return {
                "method": "callback",
                "confirmed": True,
                "exploit_data": exploit_data,
                "confidence": "CRITICAL"
            }

        return None
