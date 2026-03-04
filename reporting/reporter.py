import json
from datetime import datetime, timezone
import threading

class Reporter:


    def __init__(self):
        self.vulnerabilities = []
        self.lock = threading.Lock()

    def add_vulnerability(self, vuln_type, url, parameter, payload, severity, exploit_data=None):
        with self.lock:
            self.vulnerabilities.append({
                "vuln_type": vuln_type,
                "url": url,
                "parameter": parameter,
                "payload": payload,
                "severity": severity,
                "exploit_data": exploit_data,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

    def save_json(self, filename="report.json"):
        with open(filename, "w") as f:
            json.dump(self.vulnerabilities, f, indent=4)

    def summary(self):
        return {
            "total_vulnerabilities": len(self.vulnerabilities)
        }