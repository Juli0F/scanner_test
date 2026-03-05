# reporting/html_report.py

from datetime import datetime
from core.config import Config


class HTMLReport:
    """
    Generador de reporte HTML agrupado por fases del Cyber Kill Chain.

    Cada fase tiene su propia seccion con color e icono distintivo.
    Los hallazgos se presentan con detalles especificos segun el tipo
    de modulo (puertos, fuzzer, XSS, reverse shell).
    """

    # Colores e iconos por fase del kill chain
    PHASE_STYLES = {
        "Reconocimiento": {
            "color": "#2196F3",
            "bg": "#0D1B2A",
            "icon": "&#128269;",    # lupa
            "desc": "DNS, puertos abiertos, servicios detectados",
        },
        "Preparacion": {
            "color": "#FF9800",
            "bg": "#1A1400",
            "icon": "&#128193;",    # carpeta
            "desc": "Directorios y archivos descubiertos (fuzzing)",
        },
        "Distribucion": {
            "color": "#9C27B0",
            "bg": "#1A0D1F",
            "icon": "&#128230;",    # paquete
            "desc": "Vectores de entrega encontrados",
        },
        "Explotacion": {
            "color": "#F44336",
            "bg": "#1A0A0A",
            "icon": "&#9889;",      # rayo
            "desc": "XSS, inyeccion de comandos y otras vulnerabilidades",
        },
        "Instalacion": {
            "color": "#E91E63",
            "bg": "#1A0A12",
            "icon": "&#128274;",    # candado
            "desc": "Reverse shells y persistencia",
        },
        "Comando y Control": {
            "color": "#FF5722",
            "bg": "#1A0E08",
            "icon": "&#128225;",    # telefono
            "desc": "Callbacks confirmados, canales C2",
        },
    }

    # Colores de severidad
    SEVERITY_COLORS = {
        "CRITICAL": "#FF1744",
        "HIGH": "#FF5252",
        "MEDIUM": "#FFB300",
        "LOW": "#66BB6A",
        "INFO": "#42A5F5",
    }

    @staticmethod
    def generate(reporter, output_file="report.html"):
        """
        Genera el reporte HTML agrupado por fases del Kill Chain.

        Args:
            reporter: instancia de Reporter con hallazgos y target_info
            output_file: nombre del archivo de salida
        """
        grouped = reporter.get_grouped_by_phase()
        target_info = reporter.target_info
        summary = reporter.summary()

        html = HTMLReport._build_html(grouped, target_info, summary)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)

    @staticmethod
    def _build_html(grouped, target_info, summary):
        """Construye el HTML completo del reporte."""

        # --- Header con info del objetivo ---
        target_section = HTMLReport._build_target_section(target_info)

        # --- Resumen ejecutivo ---
        summary_section = HTMLReport._build_summary_section(summary)

        # --- Secciones por fase ---
        phases_html = ""
        for phase in Config.PHASES:
            if phase in grouped:
                phases_html += HTMLReport._build_phase_section(
                    phase, grouped[phase]
                )

        return f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ScannerV - Reporte de Seguridad</title>
    {HTMLReport._get_styles()}
</head>
<body>
    <div class="container">
        <header>
            <h1>&#128737; ScannerV - Reporte de Seguridad</h1>
            <p class="subtitle">Analisis basado en Cyber Kill Chain</p>
            <p class="timestamp">Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>

        {target_section}
        {summary_section}

        <div class="phases">
            <h2>Hallazgos por Fase</h2>
            {phases_html}
        </div>
    </div>
</body>
</html>"""

    # ----------------------------------------
    # Secciones del reporte
    # ----------------------------------------

    @staticmethod
    def _build_target_section(target_info):
        """Construye la seccion de info del objetivo."""
        if not target_info:
            return ""

        return f"""
        <div class="target-info">
            <h2>Objetivo</h2>
            <div class="info-grid">
                <div class="info-item">
                    <span class="label">Hostname</span>
                    <span class="value">{target_info.get('hostname', 'N/A')}</span>
                </div>
                <div class="info-item">
                    <span class="label">IP</span>
                    <span class="value">{target_info.get('ip', 'N/A')}</span>
                </div>
                <div class="info-item">
                    <span class="label">Callback IP</span>
                    <span class="value">{target_info.get('callback_ip', 'N/A')}</span>
                </div>
                <div class="info-item">
                    <span class="label">Callback Port</span>
                    <span class="value">{target_info.get('callback_port', 'N/A')}</span>
                </div>
                <div class="info-item">
                    <span class="label">Inicio del escaneo</span>
                    <span class="value">{target_info.get('scan_start', 'N/A')}</span>
                </div>
            </div>
        </div>"""

    @staticmethod
    def _build_summary_section(summary):
        """Construye el resumen ejecutivo."""
        total = summary.get("total_vulnerabilities", 0)
        by_severity = summary.get("by_severity", {})
        by_phase = summary.get("by_phase", {})

        # Badges de severidad
        severity_badges = ""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = by_severity.get(sev, 0)
            if count:
                color = HTMLReport.SEVERITY_COLORS.get(sev, "#888")
                severity_badges += (
                    f'<span class="badge" style="background:{color}">'
                    f'{sev}: {count}</span> '
                )

        # Barras por fase
        phase_bars = ""
        if total > 0:
            for phase in Config.PHASES:
                count = by_phase.get(phase, 0)
                if count:
                    style = HTMLReport.PHASE_STYLES.get(phase, {})
                    color = style.get("color", "#888")
                    pct = (count / total) * 100
                    phase_bars += f"""
                    <div class="phase-bar-row">
                        <span class="phase-bar-label">{phase}</span>
                        <div class="phase-bar-track">
                            <div class="phase-bar-fill"
                                 style="width:{pct:.0f}%;background:{color}">
                            </div>
                        </div>
                        <span class="phase-bar-count">{count}</span>
                    </div>"""

        return f"""
        <div class="summary">
            <h2>Resumen Ejecutivo</h2>
            <div class="summary-total">
                <span class="total-number">{total}</span>
                <span class="total-label">hallazgos totales</span>
            </div>
            <div class="severity-badges">{severity_badges}</div>
            <div class="phase-bars">{phase_bars}</div>
        </div>"""

    @staticmethod
    def _build_phase_section(phase, findings):
        """Construye una seccion completa para una fase del kill chain."""
        style = HTMLReport.PHASE_STYLES.get(phase, {})
        color = style.get("color", "#888")
        bg = style.get("bg", "#111")
        icon = style.get("icon", "")
        desc = style.get("desc", "")

        # Construir filas de hallazgos
        rows = ""
        for vuln in findings:
            rows += HTMLReport._build_vuln_row(vuln)

        return f"""
        <div class="phase-section" style="border-left:4px solid {color};">
            <div class="phase-header" style="background:{bg};">
                <h3>
                    <span class="phase-icon">{icon}</span>
                    {phase}
                    <span class="phase-count">{len(findings)}</span>
                </h3>
                <p class="phase-desc">{desc}</p>
            </div>
            <table class="findings-table">
                <thead>
                    <tr>
                        <th style="width:12%">Tipo</th>
                        <th style="width:25%">URL / Objetivo</th>
                        <th style="width:12%">Parametro</th>
                        <th style="width:25%">Payload / Info</th>
                        <th style="width:8%">Severidad</th>
                        <th style="width:18%">Detalles</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>"""

    @staticmethod
    def _build_vuln_row(vuln):
        """Construye una fila de hallazgo con detalles especificos por tipo."""
        sev = vuln.get("severity", "LOW")
        sev_color = HTMLReport.SEVERITY_COLORS.get(sev, "#888")

        # Escapar HTML en payload
        payload_escaped = HTMLReport._escape(str(vuln.get("payload", "")))
        url_escaped = HTMLReport._escape(str(vuln.get("url", "")))
        param_escaped = HTMLReport._escape(str(vuln.get("parameter", "")))

        # Construir detalles especificos segun exploit_data
        details = HTMLReport._build_exploit_details(vuln)

        return f"""
                    <tr>
                        <td>{HTMLReport._escape(vuln.get('vuln_type', ''))}</td>
                        <td class="url-cell" title="{url_escaped}">{url_escaped}</td>
                        <td><code>{param_escaped}</code></td>
                        <td class="payload-cell"><code>{payload_escaped}</code></td>
                        <td>
                            <span class="severity-tag"
                                  style="background:{sev_color}">
                                {sev}
                            </span>
                        </td>
                        <td class="details-cell">{details}</td>
                    </tr>"""

    @staticmethod
    def _build_exploit_details(vuln):
        """
        Genera HTML de detalles segun el tipo de hallazgo.
        Adapta la presentacion a cada modulo (puertos, fuzzer, XSS, etc).
        """
        exploit = vuln.get("exploit_data")
        if not exploit:
            return "<em>-</em>"

        vuln_type = vuln.get("vuln_type", "")

        # --- Open Port (port_scanner) ---
        if vuln_type == "Open Port":
            svc = exploit.get("service_info", {})
            banner = exploit.get("banner", "")
            items = []
            if svc.get("service"):
                items.append(f"<b>Servicio:</b> {HTMLReport._escape(svc['service'])}")
            if svc.get("product"):
                product = svc["product"]
                if svc.get("version"):
                    product += f" {svc['version']}"
                items.append(f"<b>Producto:</b> {HTMLReport._escape(product)}")
            if svc.get("risk"):
                items.append(f"<b>Riesgo:</b> {HTMLReport._escape(svc['risk'])}")
            if banner:
                short_banner = banner[:80] + ("..." if len(banner) > 80 else "")
                items.append(
                    f"<b>Banner:</b> <code>{HTMLReport._escape(short_banner)}</code>"
                )
            return "<br>".join(items) if items else "<em>-</em>"

        # --- Directory/File Found (fuzzer) ---
        if vuln_type == "Directory/File Found":
            items = []
            status = exploit.get("status_code")
            if status:
                items.append(f"<b>Status:</b> {status}")
            length = exploit.get("content_length")
            if length:
                items.append(f"<b>Tamano:</b> {length} bytes")
            title = exploit.get("title")
            if title:
                items.append(f"<b>Titulo:</b> {HTMLReport._escape(title)}")
            redirect = exploit.get("redirect")
            if redirect:
                items.append(
                    f"<b>Redirect:</b> {HTMLReport._escape(redirect)}"
                )
            if exploit.get("sensitive"):
                items.append('<b style="color:#FF1744">&#9888; SENSIBLE</b>')
            return "<br>".join(items) if items else "<em>-</em>"

        # --- XSS (callback data) ---
        if "XSS" in vuln_type:
            items = []
            if exploit.get("ip"):
                items.append(f"<b>Victim IP:</b> {HTMLReport._escape(str(exploit['ip']))}")
            if exploit.get("user_agent"):
                items.append(
                    f"<b>User-Agent:</b> {HTMLReport._escape(str(exploit['user_agent']))}"
                )
            if exploit.get("cookies"):
                items.append(
                    f"<b>Cookies:</b> <code>{HTMLReport._escape(str(exploit['cookies']))}</code>"
                )
            if exploit.get("timestamp"):
                items.append(f"<b>Timestamp:</b> {HTMLReport._escape(str(exploit['timestamp']))}")
            return "<br>".join(items) if items else "<em>Reflected (sin callback)</em>"

        # --- Command Injection / Reverse Shell ---
        if "Command" in vuln_type or "Reverse Shell" in vuln_type:
            items = []
            method = exploit.get("detection_method")
            if method:
                items.append(f"<b>Metodo:</b> {HTMLReport._escape(method)}")
            details = exploit.get("detection_details", {})
            if details.get("confidence"):
                items.append(f"<b>Confianza:</b> {HTMLReport._escape(details['confidence'])}")
            if details.get("elapsed"):
                items.append(f"<b>Tiempo:</b> {details['elapsed']:.2f}s")
            if details.get("matched_pattern"):
                items.append(
                    f"<b>Patron:</b> <code>"
                    f"{HTMLReport._escape(str(details['matched_pattern']))}</code>"
                )
            return "<br>".join(items) if items else "<em>-</em>"

        # --- Fallback generico ---
        items = []
        for key, val in exploit.items():
            if val is not None and val != "":
                items.append(
                    f"<b>{HTMLReport._escape(key)}:</b> "
                    f"{HTMLReport._escape(str(val)[:100])}"
                )
        return "<br>".join(items[:5]) if items else "<em>-</em>"

    # ----------------------------------------
    # CSS
    # ----------------------------------------

    @staticmethod
    def _get_styles():
        return """
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #0A0E17;
            color: #E0E0E0;
            line-height: 1.6;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            text-align: center;
            padding: 30px 0;
            border-bottom: 2px solid #1E2A3A;
            margin-bottom: 30px;
        }

        header h1 {
            color: #00E676;
            font-size: 2em;
            margin-bottom: 5px;
        }

        .subtitle {
            color: #78909C;
            font-size: 1.1em;
        }

        .timestamp {
            color: #546E7A;
            font-size: 0.85em;
            margin-top: 5px;
        }

        /* Target info */
        .target-info {
            background: #111827;
            border: 1px solid #1E2A3A;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 25px;
        }

        .target-info h2 {
            color: #4FC3F7;
            margin-bottom: 15px;
            font-size: 1.2em;
        }

        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
        }

        .info-item {
            background: #1A2332;
            padding: 10px 15px;
            border-radius: 6px;
        }

        .info-item .label {
            display: block;
            color: #78909C;
            font-size: 0.8em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .info-item .value {
            display: block;
            color: #E0E0E0;
            font-weight: 600;
            font-size: 0.95em;
            word-break: break-all;
        }

        /* Summary */
        .summary {
            background: #111827;
            border: 1px solid #1E2A3A;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
        }

        .summary h2 {
            color: #4FC3F7;
            margin-bottom: 15px;
            font-size: 1.2em;
        }

        .summary-total {
            text-align: center;
            margin-bottom: 15px;
        }

        .total-number {
            font-size: 3em;
            font-weight: 700;
            color: #00E676;
            display: block;
        }

        .total-label {
            color: #78909C;
            font-size: 0.9em;
        }

        .severity-badges {
            text-align: center;
            margin-bottom: 20px;
        }

        .badge {
            display: inline-block;
            padding: 5px 14px;
            border-radius: 20px;
            color: #fff;
            font-weight: 600;
            font-size: 0.85em;
            margin: 3px;
        }

        .phase-bars {
            max-width: 600px;
            margin: 0 auto;
        }

        .phase-bar-row {
            display: flex;
            align-items: center;
            margin: 6px 0;
        }

        .phase-bar-label {
            width: 160px;
            font-size: 0.85em;
            color: #B0BEC5;
            text-align: right;
            padding-right: 12px;
        }

        .phase-bar-track {
            flex: 1;
            height: 16px;
            background: #1A2332;
            border-radius: 8px;
            overflow: hidden;
        }

        .phase-bar-fill {
            height: 100%;
            border-radius: 8px;
            transition: width 0.3s;
        }

        .phase-bar-count {
            width: 40px;
            text-align: right;
            font-size: 0.85em;
            font-weight: 600;
            color: #E0E0E0;
            padding-left: 8px;
        }

        /* Phase sections */
        .phases h2 {
            color: #4FC3F7;
            margin-bottom: 20px;
            font-size: 1.3em;
        }

        .phase-section {
            margin-bottom: 30px;
            border-radius: 8px;
            overflow: hidden;
            background: #111827;
        }

        .phase-header {
            padding: 15px 20px;
        }

        .phase-header h3 {
            color: #fff;
            font-size: 1.15em;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .phase-icon {
            font-size: 1.3em;
        }

        .phase-count {
            background: rgba(255,255,255,0.15);
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 0.75em;
            margin-left: 8px;
        }

        .phase-desc {
            color: #78909C;
            font-size: 0.85em;
            margin-top: 4px;
        }

        /* Findings table */
        .findings-table {
            width: 100%;
            border-collapse: collapse;
        }

        .findings-table th {
            background: #1A2332;
            color: #90A4AE;
            font-size: 0.8em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid #263238;
        }

        .findings-table td {
            padding: 10px 12px;
            border-bottom: 1px solid #1E2A3A;
            font-size: 0.88em;
            vertical-align: top;
        }

        .findings-table tbody tr:hover {
            background: rgba(255,255,255,0.03);
        }

        .url-cell {
            word-break: break-all;
            max-width: 300px;
        }

        .payload-cell code {
            background: #1A2332;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.85em;
            word-break: break-all;
            display: inline-block;
            max-width: 100%;
        }

        .details-cell {
            font-size: 0.82em;
            line-height: 1.7;
        }

        .details-cell code {
            background: #1A2332;
            padding: 1px 4px;
            border-radius: 3px;
            font-size: 0.9em;
        }

        .severity-tag {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 4px;
            color: #fff;
            font-weight: 700;
            font-size: 0.75em;
            text-align: center;
        }

        code {
            font-family: 'Consolas', 'Monaco', monospace;
        }

        /* Responsive */
        @media (max-width: 900px) {
            .info-grid { grid-template-columns: 1fr 1fr; }
            .findings-table { font-size: 0.8em; }
            .phase-bar-label { width: 120px; }
        }
    </style>"""

    # ----------------------------------------
    # Utilidades
    # ----------------------------------------

    @staticmethod
    def _escape(text):
        """Escapa caracteres HTML peligrosos."""
        if not text:
            return ""
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )
