import re


class ServiceDetector:
    """
    Identifica servicios asociados a puertos abiertos usando:
    1. Base de datos de puertos conocidos (well-known ports)
    2. Analisis de banners capturados (fingerprinting)
    """

    # -------------------------------------------------
    # Base de datos de puertos conocidos
    # -------------------------------------------------
    WELL_KNOWN_PORTS = {
        20: {"service": "FTP Data", "protocol": "tcp", "risk": "MEDIUM"},
        21: {"service": "FTP", "protocol": "tcp", "risk": "HIGH"},
        22: {"service": "SSH", "protocol": "tcp", "risk": "LOW"},
        23: {"service": "Telnet", "protocol": "tcp", "risk": "CRITICAL"},
        25: {"service": "SMTP", "protocol": "tcp", "risk": "MEDIUM"},
        53: {"service": "DNS", "protocol": "tcp/udp", "risk": "MEDIUM"},
        69: {"service": "TFTP", "protocol": "udp", "risk": "HIGH"},
        80: {"service": "HTTP", "protocol": "tcp", "risk": "LOW"},
        110: {"service": "POP3", "protocol": "tcp", "risk": "MEDIUM"},
        111: {"service": "RPCbind", "protocol": "tcp", "risk": "HIGH"},
        119: {"service": "NNTP", "protocol": "tcp", "risk": "MEDIUM"},
        135: {"service": "MS-RPC", "protocol": "tcp", "risk": "HIGH"},
        137: {"service": "NetBIOS Name", "protocol": "udp", "risk": "HIGH"},
        138: {"service": "NetBIOS Datagram", "protocol": "udp", "risk": "HIGH"},
        139: {"service": "NetBIOS Session", "protocol": "tcp", "risk": "HIGH"},
        143: {"service": "IMAP", "protocol": "tcp", "risk": "MEDIUM"},
        161: {"service": "SNMP", "protocol": "udp", "risk": "HIGH"},
        162: {"service": "SNMP Trap", "protocol": "udp", "risk": "HIGH"},
        389: {"service": "LDAP", "protocol": "tcp", "risk": "MEDIUM"},
        443: {"service": "HTTPS", "protocol": "tcp", "risk": "LOW"},
        445: {"service": "SMB", "protocol": "tcp", "risk": "HIGH"},
        465: {"service": "SMTPS", "protocol": "tcp", "risk": "LOW"},
        514: {"service": "Syslog", "protocol": "udp", "risk": "MEDIUM"},
        515: {"service": "LPD", "protocol": "tcp", "risk": "MEDIUM"},
        587: {"service": "SMTP Submission", "protocol": "tcp", "risk": "LOW"},
        631: {"service": "IPP/CUPS", "protocol": "tcp", "risk": "MEDIUM"},
        636: {"service": "LDAPS", "protocol": "tcp", "risk": "LOW"},
        993: {"service": "IMAPS", "protocol": "tcp", "risk": "LOW"},
        995: {"service": "POP3S", "protocol": "tcp", "risk": "LOW"},
        1080: {"service": "SOCKS Proxy", "protocol": "tcp", "risk": "HIGH"},
        1433: {"service": "MS-SQL", "protocol": "tcp", "risk": "CRITICAL"},
        1434: {"service": "MS-SQL Monitor", "protocol": "udp", "risk": "CRITICAL"},
        1521: {"service": "Oracle DB", "protocol": "tcp", "risk": "CRITICAL"},
        1723: {"service": "PPTP VPN", "protocol": "tcp", "risk": "MEDIUM"},
        2049: {"service": "NFS", "protocol": "tcp", "risk": "HIGH"},
        2181: {"service": "ZooKeeper", "protocol": "tcp", "risk": "HIGH"},
        3306: {"service": "MySQL", "protocol": "tcp", "risk": "CRITICAL"},
        3389: {"service": "RDP", "protocol": "tcp", "risk": "CRITICAL"},
        5432: {"service": "PostgreSQL", "protocol": "tcp", "risk": "CRITICAL"},
        5672: {"service": "RabbitMQ", "protocol": "tcp", "risk": "HIGH"},
        5900: {"service": "VNC", "protocol": "tcp", "risk": "CRITICAL"},
        5901: {"service": "VNC :1", "protocol": "tcp", "risk": "CRITICAL"},
        6379: {"service": "Redis", "protocol": "tcp", "risk": "CRITICAL"},
        6443: {"service": "Kubernetes API", "protocol": "tcp", "risk": "HIGH"},
        8000: {"service": "HTTP Alt", "protocol": "tcp", "risk": "LOW"},
        8080: {"service": "HTTP Proxy", "protocol": "tcp", "risk": "MEDIUM"},
        8443: {"service": "HTTPS Alt", "protocol": "tcp", "risk": "LOW"},
        8888: {"service": "HTTP Alt", "protocol": "tcp", "risk": "MEDIUM"},
        9090: {"service": "Prometheus", "protocol": "tcp", "risk": "MEDIUM"},
        9200: {"service": "Elasticsearch", "protocol": "tcp", "risk": "HIGH"},
        9300: {"service": "Elasticsearch Cluster", "protocol": "tcp", "risk": "HIGH"},
        11211: {"service": "Memcached", "protocol": "tcp", "risk": "HIGH"},
        27017: {"service": "MongoDB", "protocol": "tcp", "risk": "CRITICAL"},
        27018: {"service": "MongoDB Shard", "protocol": "tcp", "risk": "CRITICAL"},
        50000: {"service": "SAP", "protocol": "tcp", "risk": "HIGH"},
    }

    # -------------------------------------------------
    # Patrones de banner para fingerprinting
    # -------------------------------------------------
    BANNER_PATTERNS = [
        # SSH
        (re.compile(r"SSH-(\d[\d.]*)-OpenSSH[_ ](\S+)", re.I),
         lambda m: {"service": "SSH", "product": "OpenSSH", "version": m.group(2),
                     "protocol_version": m.group(1)}),

        (re.compile(r"SSH-(\d[\d.]*)-(.+)", re.I),
         lambda m: {"service": "SSH", "product": m.group(2).strip(),
                     "protocol_version": m.group(1)}),

        # FTP
        (re.compile(r"220[- ].*vsftpd\s+(\S+)", re.I),
         lambda m: {"service": "FTP", "product": "vsftpd", "version": m.group(1)}),

        (re.compile(r"220[- ].*ProFTPD\s+(\S+)", re.I),
         lambda m: {"service": "FTP", "product": "ProFTPD", "version": m.group(1)}),

        (re.compile(r"220[- ].*FileZilla Server\s+(\S+)", re.I),
         lambda m: {"service": "FTP", "product": "FileZilla Server",
                     "version": m.group(1)}),

        (re.compile(r"220[- ].*Microsoft FTP Service", re.I),
         lambda m: {"service": "FTP", "product": "Microsoft FTP Service"}),

        (re.compile(r"220[- ].*FTP", re.I),
         lambda m: {"service": "FTP", "product": "Unknown FTP"}),

        # SMTP
        (re.compile(r"220[- ].*Postfix", re.I),
         lambda m: {"service": "SMTP", "product": "Postfix"}),

        (re.compile(r"220[- ].*Exim\s+(\S+)", re.I),
         lambda m: {"service": "SMTP", "product": "Exim", "version": m.group(1)}),

        (re.compile(r"220[- ].*Microsoft ESMTP", re.I),
         lambda m: {"service": "SMTP", "product": "Microsoft Exchange"}),

        (re.compile(r"220[- ].*SMTP", re.I),
         lambda m: {"service": "SMTP", "product": "Unknown SMTP"}),

        # HTTP
        (re.compile(r"HTTP/[\d.]+ \d+.*Server:\s*Apache/([\d.]+)", re.I | re.S),
         lambda m: {"service": "HTTP", "product": "Apache", "version": m.group(1)}),

        (re.compile(r"HTTP/[\d.]+ \d+.*Server:\s*nginx/([\d.]+)", re.I | re.S),
         lambda m: {"service": "HTTP", "product": "nginx", "version": m.group(1)}),

        (re.compile(r"HTTP/[\d.]+ \d+.*Server:\s*Microsoft-IIS/([\d.]+)", re.I | re.S),
         lambda m: {"service": "HTTP", "product": "IIS", "version": m.group(1)}),

        (re.compile(r"HTTP/[\d.]+\s+\d+", re.I),
         lambda m: {"service": "HTTP", "product": "Unknown HTTP Server"}),

        # MySQL
        (re.compile(r"(\d+\.\d+\.\d+).*mysql", re.I),
         lambda m: {"service": "MySQL", "product": "MySQL", "version": m.group(1)}),

        (re.compile(r"mysql", re.I),
         lambda m: {"service": "MySQL", "product": "MySQL"}),

        # PostgreSQL
        (re.compile(r"PostgreSQL", re.I),
         lambda m: {"service": "PostgreSQL", "product": "PostgreSQL"}),

        # Redis
        (re.compile(r"-ERR.*redis|REDIS", re.I),
         lambda m: {"service": "Redis", "product": "Redis"}),

        # MongoDB
        (re.compile(r"MongoDB|ismaster", re.I),
         lambda m: {"service": "MongoDB", "product": "MongoDB"}),

        # RDP
        (re.compile(rb"\x03\x00".decode("latin-1"), re.I),
         lambda m: {"service": "RDP", "product": "RDP"}),

        # Telnet
        (re.compile(r"login:|Username:", re.I),
         lambda m: {"service": "Telnet", "product": "Telnet"}),

        # POP3
        (re.compile(r"\+OK.*POP3|Dovecot", re.I),
         lambda m: {"service": "POP3", "product": "POP3 Server"}),

        # IMAP
        (re.compile(r"\* OK.*IMAP", re.I),
         lambda m: {"service": "IMAP", "product": "IMAP Server"}),
    ]

    @classmethod
    def identify_by_port(cls, port):
        """
        Identifica un servicio usando la base de datos de puertos conocidos.

        Returns:
            dict con info del servicio o None
        """
        info = cls.WELL_KNOWN_PORTS.get(port)
        if info:
            return {
                "port": port,
                "service": info["service"],
                "protocol": info["protocol"],
                "risk": info["risk"],
                "source": "well_known_port"
            }
        return None

    @classmethod
    def identify_by_banner(cls, banner):
        """
        Analiza un banner capturado para identificar el servicio y version.

        Returns:
            dict con info del servicio o None
        """
        if not banner:
            return None

        for pattern, extractor in cls.BANNER_PATTERNS:
            match = pattern.search(banner)
            if match:
                result = extractor(match)
                result["source"] = "banner"
                result["raw_banner"] = banner[:200]
                return result

        return None

    @classmethod
    def identify(cls, port, banner=None):
        """
        Identifica un servicio combinando informacion del puerto y banner.
        El banner tiene prioridad si esta disponible.

        Returns:
            dict con toda la info del servicio
        """
        port_info = cls.identify_by_port(port)
        banner_info = cls.identify_by_banner(banner) if banner else None

        if banner_info and port_info:
            # Combinar: banner tiene prioridad pero conservar risk del port
            result = {**port_info, **banner_info}
            result["source"] = "banner+port"
            return result

        if banner_info:
            banner_info["port"] = port
            if "risk" not in banner_info:
                banner_info["risk"] = "MEDIUM"
            return banner_info

        if port_info:
            return port_info

        # Puerto desconocido sin banner reconocible
        return {
            "port": port,
            "service": "Unknown",
            "protocol": "tcp",
            "risk": "INFO",
            "source": "unknown",
            "raw_banner": banner[:200] if banner else None
        }

    @classmethod
    def get_risk_for_open_port(cls, port, service_info):
        """
        Evalua el riesgo de un puerto abierto basandose en el servicio.
        Retorna severidad compatible con el Reporter.
        """
        risk = service_info.get("risk", "INFO")

        risk_to_severity = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
            "INFO": "LOW",
        }

        return risk_to_severity.get(risk, "LOW")
