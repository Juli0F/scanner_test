# core/config.py

import socket
import requests
from urllib.parse import urlparse


class Config:
    # Configuracion general
    TIMEOUT = 10
    DELAY = 1
    MAX_RETRIES = 5
    BASE_DELAY = 1

    # Crawler
    MAX_DEPTH = 2

    # Callback server
    CALLBACK_PORT = 8000

    # Headers por defecto
    USER_AGENT = "ScannerAcademico/2.0"

    # Fases del Cyber Kill Chain
    PHASES = [
        "Reconocimiento",
        "Preparacion",
        "Distribucion",
        "Explotacion",
        "Instalacion",
        "Comando y Control",
    ]


def resolve_target(url):
    """
    Resuelve el hostname de una URL a su IP.
    Retorna (hostname, ip) o (hostname, None) si falla.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname and "://" not in url:
        parsed = urlparse(f"http://{url}")
        hostname = parsed.hostname

    if not hostname:
        hostname = url.split("://")[-1].split("/")[0].split(":")[0]

    try:
        ip = socket.gethostbyname(hostname)
        return hostname, ip
    except socket.gaierror:
        return hostname, None


def get_local_ip():
    """
    Detecta la IP local de la interfaz de red activa.
    Crea una conexion UDP dummy para determinar que interfaz
    usaria el SO para salir a internet.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return "127.0.0.1"


def create_session():
    """
    Crea y configura una sesion reutilizable.
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": Config.USER_AGENT,
        "Accept": "*/*",
        "Connection": "keep-alive"
    })
    return session