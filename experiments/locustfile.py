"""Locust workload for the SIARC /analyze endpoint."""
import os
import random
from datetime import datetime, timezone
from locust import HttpUser, task, between

API_KEY = os.environ.get("SIARC_API_KEY", "siarc-benchmark-key")
RUN_ID = os.environ.get("SIARC_RUN_ID", "manual-locust")

class SIARCLoadTestUser(HttpUser):
    wait_time = between(0.01, 0.05)

    def on_start(self):
        self.client.headers.update({"X-API-Key": API_KEY})

    def _payload(self, critical: bool = False):
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": f"203.0.113.{random.randint(1,254)}" if critical else f"10.0.0.{random.randint(1,254)}",
            "dst_ip": "192.168.10.20",
            "event_type": "exploit_attempt" if critical else random.choice(["port_scan", "brute_force", "unknown"]),
            "severity": "critical" if critical else random.choice(["low", "medium", "high"]),
            "payload": "user_email=usuario.teste@empresa.com.br CVE-2024-0001 shellcode" if critical else "login usuario.teste@empresa.com.br source=10.0.0.44",
            "extra": {"dataset_label": "attack" if critical else "mixed", "experiment_run_id": RUN_ID},
        }

    @task(4)
    def monitored(self):
        self.client.post("/analyze", json=self._payload(False), name="/analyze")

    @task(1)
    def critical(self):
        self.client.post("/analyze", json=self._payload(True), name="/analyze")
