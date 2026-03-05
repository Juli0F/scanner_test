class Wordlist:
    """
    Wordlist embebida para fuzzing de directorios y archivos.
    Tambien soporta carga desde archivo externo.
    """

    # Directorios comunes
    DIRECTORIES = [
        "admin", "administrator", "login", "wp-admin", "wp-login",
        "cpanel", "dashboard", "panel", "portal", "console",
        "phpmyadmin", "pma", "adminer", "mysql", "db",
        "api", "api/v1", "api/v2", "rest", "graphql",
        "backup", "backups", "bak", "old", "temp", "tmp",
        "uploads", "upload", "files", "media", "images", "img",
        "assets", "static", "public", "private", "data",
        "config", "conf", "configuration", "settings", "setup",
        "install", "installer", "test", "tests", "testing",
        "dev", "development", "staging", "debug",
        "docs", "doc", "documentation", "help", "readme",
        "server-status", "server-info", "status", "health",
        "info", "phpinfo", "info.php", "test.php",
        "cgi-bin", "scripts", "bin", "includes", "include",
        "lib", "libs", "vendor", "node_modules", "packages",
        "wp-content", "wp-includes", "wp-json",
        "xmlrpc.php", "wp-cron.php", "wp-config.php",
        ".git", ".svn", ".env", ".htaccess", ".htpasswd",
        ".DS_Store", "web.config", "crossdomain.xml",
        "robots.txt", "sitemap.xml", "humans.txt", "security.txt",
        ".well-known", ".well-known/security.txt",
        "swagger", "swagger-ui", "api-docs", "openapi",
        "graphiql", "playground",
        "logs", "log", "error_log", "access_log",
        "shell", "cmd", "command", "exec", "terminal",
        "secret", "secrets", "hidden", "internal",
        "user", "users", "account", "accounts", "profile",
        "register", "signup", "signin", "auth", "oauth",
        "token", "tokens", "session", "sessions",
        "download", "downloads", "export", "import",
        "manage", "manager", "management",
        "monitor", "monitoring", "metrics", "prometheus",
        "elastic", "elasticsearch", "kibana", "grafana",
        "jenkins", "travis", "ci", "cd",
        "docker", "kubernetes", "k8s",
        "redis", "memcached", "cache",
        "mail", "email", "webmail", "smtp",
        "ftp", "sftp", "ssh",
        "proxy", "gateway", "load-balancer",
        "socket", "websocket", "ws",
    ]

    # Archivos comunes sensibles
    FILES = [
        "robots.txt", "sitemap.xml", "crossdomain.xml",
        ".env", ".env.local", ".env.production", ".env.backup",
        ".git/config", ".git/HEAD", ".gitignore",
        ".svn/entries", ".svn/wc.db",
        ".htaccess", ".htpasswd",
        "web.config", "Web.config",
        "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
        "config.php", "config.inc.php", "configuration.php",
        "database.yml", "database.php", "db.php",
        "settings.py", "settings.ini", "local_settings.py",
        "application.yml", "application.properties",
        "config.json", "config.yaml", "config.yml",
        "package.json", "composer.json", "Gemfile",
        "requirements.txt", "Pipfile", "Cargo.toml",
        "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
        "Makefile", "Vagrantfile", "Procfile",
        "phpinfo.php", "info.php", "test.php", "pi.php",
        "adminer.php", "phpmyadmin/index.php",
        "server-status", "server-info",
        "elmah.axd", "trace.axd",
        "id_rsa", "id_dsa", ".ssh/id_rsa",
        "backup.sql", "dump.sql", "database.sql", "db.sql",
        "backup.zip", "backup.tar.gz", "site.zip",
        "error.log", "debug.log", "access.log",
        "changelog.txt", "readme.txt", "README.md", "LICENSE",
        "INSTALL", "CHANGELOG", "VERSION",
        "humans.txt", "security.txt", ".well-known/security.txt",
        "favicon.ico", "manifest.json",
        "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
        "api/swagger.json", "api/openapi.json",
    ]

    # Extensiones para probar con cada directorio
    EXTENSIONS = [
        "", ".php", ".html", ".htm", ".asp", ".aspx",
        ".jsp", ".py", ".rb", ".txt", ".xml", ".json",
        ".bak", ".old", ".orig", ".save", ".swp",
        ".zip", ".tar.gz", ".sql",
    ]

    @classmethod
    def get_default(cls):
        """Retorna la wordlist completa (directorios + archivos)."""
        words = set()
        words.update(cls.DIRECTORIES)
        words.update(cls.FILES)
        return sorted(words)

    @classmethod
    def get_with_extensions(cls):
        """Retorna directorios con extensiones variadas."""
        words = set()

        # Archivos tal cual
        words.update(cls.FILES)

        # Directorios con y sin extensiones
        for directory in cls.DIRECTORIES:
            for ext in cls.EXTENSIONS:
                words.add(f"{directory}{ext}")

        return sorted(words)

    @classmethod
    def load_from_file(cls, filepath):
        """Carga wordlist desde archivo externo (una palabra por linea)."""
        words = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    word = line.strip()
                    if word and not word.startswith("#"):
                        words.append(word)
        except FileNotFoundError:
            print(f"[Fuzzer] Wordlist no encontrada: {filepath}")
        return words
