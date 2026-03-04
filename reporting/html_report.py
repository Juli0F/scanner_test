# reporting/html_report.py

from datetime import datetime


class HTMLReport:

    @staticmethod
    def generate(vulnerabilities, output_file="report.html"):

        severity_colors = {
            "CRITICAL": "#8B0000",
            "HIGH": "#FF0000",
            "MEDIUM": "#FFA500",
            "LOW": "#FFFF00"
        }

        rows = ""

        for vuln in vulnerabilities:

            color = severity_colors.get(vuln["severity"], "#FFFFFF")

            exploit_info = ""

            if vuln.get("exploit_data"):
                exploit = vuln["exploit_data"]

                exploit_info = f"""
                <ul>
                    <li><strong>Victim IP:</strong> {exploit.get('ip')}</li>
                    <li><strong>User-Agent:</strong> {exploit.get('user_agent')}</li>
                    <li><strong>Cookies:</strong> {exploit.get('cookies')}</li>
                    <li><strong>Timestamp:</strong> {exploit.get('timestamp')}</li>
                </ul>
                """

            rows += f"""
            <tr style="background-color:{color};">
                <td>{vuln["vuln_type"]}</td>
                <td>{vuln["url"]}</td>
                <td>{vuln["parameter"]}</td>
                <td><code>{vuln["payload"]}</code></td>
                <td>{vuln["severity"]}</td>
                <td>{exploit_info}</td>
            </tr>
            """

        html_content = f"""
        <html>
        <head>
            <title>Security Scan Report</title>
            <style>
                body {{ font-family: Arial; background-color: #111; color: #eee; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #444; padding: 8px; }}
                th {{ background-color: #222; }}
                h1 {{ color: #00FFAA; }}
            </style>
        </head>
        <body>
            <h1>Security Scan Report</h1>
            <p>Generated: {datetime.now()}</p>

            <table>
                <tr>
                    <th>Type</th>
                    <th>URL</th>
                    <th>Parameter</th>
                    <th>Payload</th>
                    <th>Severity</th>
                    <th>Exploit Details</th>
                </tr>
                {rows}
            </table>
        </body>
        </html>
        """

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)