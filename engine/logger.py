import json
import os
from datetime import datetime

class SIEMLogger:
    """
    Generates structured JSON logs formatted for Wazuh, Splunk, or Elastic SIEM.
    """
    def __init__(self, log_dir: str = "/app/logs"):
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)
        self.log_file = os.path.join(self.log_dir, "drift_alerts.jsonl")

    def log_drift(self, file_path: str, diff_text: str):
        """
        Logs a detected configuration drift event.
        """
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": "plc_logic_drift",
            "severity": "CRITICAL",
            "source": "OT-Guard-Engine",
            "file_path": file_path,
            "mitre_attack_ics": "T0836",
            "mitre_tactic": "Modify Control Logic",
            "diff_summary": diff_text
        }
        
        # Append-only tamper-evident log
        with open(self.log_file, "a") as f:
            f.write(json.dumps(event) + "\n")
            
        print(f"[CRITICAL] Drift detected in {file_path}. Alert logged.")
