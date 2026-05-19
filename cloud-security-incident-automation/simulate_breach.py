#!/usr/bin/env python3
"""
Cloud Security Breach Simulation Script
Simulates unauthorized access attempts to cloud object storage.
"""

import json
import random
import datetime
import time
from pathlib import Path


class S3BreachSimulator:
    def __init__(self, config_file: str):
        with open(config_file, "r") as f:
            self.config = json.load(f)

        self.suspicious_ips = [
            "203.0.113.45",
            "198.51.100.23",
            "192.0.2.100",
            "172.16.254.1"
        ]

        self.unauthorized_users = [
            "hacker@malicious.com",
            "unknown@suspicious.org",
            "attacker@evil.net"
        ]

    def generate_access_log(self, is_breach: bool = False) -> dict:
        timestamp = datetime.datetime.now(datetime.UTC).isoformat()

        if is_breach:
            source_ip = random.choice(self.suspicious_ips)
            user = random.choice(self.unauthorized_users)
            action = random.choice(["GET", "PUT", "DELETE"])
            status_code = random.choice([200, 403, 401])
            object_key = random.choice([
                "confidential/financial_data.xlsx",
                "secrets/api_keys.txt",
                "private/customer_database.sql"
            ])
        else:
            source_ip = random.choice(self.config["authorized_ips"])
            user = random.choice(self.config["authorized_users"])
            action = "GET"
            status_code = 200
            object_key = "public/readme.txt"

        return {
            "timestamp": timestamp,
            "bucket": self.config["bucket_name"],
            "source_ip": source_ip,
            "user": user,
            "action": action,
            "object_key": object_key,
            "status_code": status_code,
            "user_agent": "aws-cli/2.15 Python/3.12",
            "request_id": f"REQ{random.randint(100000, 999999)}"
        }

    def simulate_breach_scenario(self, num_logs: int = 15) -> list[dict]:
        logs = []

        print(f"Simulating {num_logs} cloud storage access attempts...")

        for i in range(num_logs):
            is_breach = random.random() < 0.35
            log_entry = self.generate_access_log(is_breach)
            logs.append(log_entry)

            if is_breach:
                print(f"⚠️ Breach attempt #{i + 1}: {log_entry['source_ip']} -> {log_entry['object_key']}")
            else:
                print(f"✅ Normal access #{i + 1}: {log_entry['source_ip']}")

            time.sleep(0.2)

        return logs

    def save_logs(self, logs: list[dict], filename: str):
        output_path = Path(filename)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            for log in logs:
                f.write(json.dumps(log) + "\n")

        print(f"📁 Logs saved to {output_path}")


def main():
    print("🔒 Starting Cloud Security Breach Simulation")
    print("=" * 50)

    simulator = S3BreachSimulator("config/aws_config.json")
    logs = simulator.simulate_breach_scenario(15)

    log_filename = f"logs/s3_access_logs_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    simulator.save_logs(logs, log_filename)

    print("\n🎯 Breach simulation completed.")
    print(f"Generated {len(logs)} log entries.")
    print("Ready for breach detection analysis.")


if __name__ == "__main__":
    main()
