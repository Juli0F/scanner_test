import json
from datetime import datetime, timezone
import threading

from core.config import Config


class Reporter:

    def __init__(self):
        self.vulnerabilities = []
        self.target_info = {}
        self.lock = threading.Lock()

    def set_target_info(self, hostname, ip, callback_ip, callback_port):
        """Guarda informacion general del objetivo."""
        with self.lock:
            self.target_info = {
                "hostname": hostname,
                "ip": ip,
                "callback_ip": callback_ip,
                "callback_port": callback_port,
                "scan_start": datetime.now(timezone.utc).isoformat()
            }

    def add_vulnerability(self, vuln_type, url, parameter, payload,
                          severity, phase=None, exploit_data=None):
        with self.lock:
            self.vulnerabilities.append({
                "phase": phase or "Sin fase",
                "vuln_type": vuln_type,
                "url": url,
                "parameter": parameter,
                "payload": payload,
                "severity": severity,
                "exploit_data": exploit_data,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

    def get_by_phase(self, phase):
        """Retorna hallazgos filtrados por fase."""
        with self.lock:
            return [v for v in self.vulnerabilities if v["phase"] == phase]

    def get_grouped_by_phase(self):
        """Retorna hallazgos agrupados por fase en orden del kill chain."""
        grouped = {}
        for phase in Config.PHASES:
            items = self.get_by_phase(phase)
            if items:
                grouped[phase] = items
        return grouped

    def save_json(self, filename="report.json"):
        data = {
            "target_info": self.target_info,
            "scan_end": datetime.now(timezone.utc).isoformat(),
            "summary": self.summary(),
            "findings": self.vulnerabilities
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

    def summary(self):
        phase_counts = {}
        severity_counts = {}

        for v in self.vulnerabilities:
            phase = v.get("phase", "Sin fase")
            phase_counts[phase] = phase_counts.get(phase, 0) + 1

            sev = v.get("severity", "LOW")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "total_vulnerabilities": len(self.vulnerabilities),
            "by_phase": phase_counts,
            "by_severity": severity_counts,
        }
