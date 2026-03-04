# core/config.py

import requests


class Config:
    # Configuracion general
    TIMEOUT = 10
    DELAY = 1
    MAX_RETRIES = 5
    BASE_DELAY = 1

    # Crawler
    MAX_DEPTH = 2

    # Headers por defecto
    USER_AGENT = "ScannerAcademico/2.0"


def create_session():
    """
    Crea y configura una sesión reutilizable.
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": Config.USER_AGENT,
        "Accept": "*/*",
        "Connection": "keep-alive"
    })
    return session