#!/usr/bin/env python3
"""
Cloud Security Breach Detection Engine
Analyzes simulated cloud storage access logs and detects security incidents.
"""

import json
import datetime
import re
import os
import glob
from pathlib import Path
from collections import defaultdict


class SecurityBreachDetector:
    def __init__(self, config_file: str):
        with open(config_file, "r") as f:
            self.config = json.load(f)

        self.breach_rules = {
            "unauthorized_ip": {
                "severity": "HIGH",
                "description": "Access from unauthorized IP address"
            },
            "unauthorized_user": {
                "severity": "HIGH",
                "description": "Access attempt by unauthorized user"
            },
            "suspicious_object": {
                "severity": "MEDIUM",
                "description": "Access to sensitive or confidential files"
            },
            "failed_auth": {
                "severity": "MEDIUM",
                "description": "Failed authentication or authorization attempt"
            },
            "unusual_activity": {
                "severity": "LOW",
                "description": "Unusual access pattern detected"
            }
        }

        self.sensitive_patterns = [
            r".*confidential.*",
            r".*secret.*",
            r".*private.*",
            r".*api[_-]?key.*",
            r".*password.*",
            r".*financial.*",
            r".*customer_database.*"
        ]

    def load_logs(self, log_file: str) -> list[dict]:
        logs = []

        try:
            with open(log_file, "r") as f:
                for line in f:
                    if line.strip():
                        logs.append(json.loads(line.strip()))

            print(f"📊 Loaded {len(logs)} log entries for analysis")
            return logs

        except FileNotFoundError:
            print(f"❌ Error: Log file {log_file} not found")
            return []

        except json.JSONDecodeError as e:
            print(f"❌ Error parsing log file: {e}")
            return []

    def check_unauthorized_ip(self, log_entry: dict) -> bool:
        return log_entry.get("source_ip", "") not in self.config.get("authorized_ips", [])

    def check_unauthorized_user(self, log_entry: dict) -> bool:
        return log_entry.get("user", "") not in self.config.get("authorized_users", [])

    def check_sensitive_file_access(self, log_entry: dict) -> bool:
        object_key = log_entry.get("object_key", "").lower()

        return any(re.match(pattern, object_key) for pattern in self.sensitive_patterns)

    def check_failed_authentication(self, log_entry: dict) -> bool:
        return log_entry.get("status_code", 200) in [401, 403]

    def analyze_access_patterns(self, logs: list[dict]) -> dict:
        ip_counts = defaultdict(int)
        user_counts = defaultdict(int)

        for log in logs:
            ip_counts[log.get("source_ip", "")] += 1
            user_counts[log.get("user", "")] += 1

        suspicious_ips = [ip for ip, count in ip_counts.items() if count > 5]
        suspicious_users = [user for user, count in user_counts.items() if count > 5]

        return {
            "suspicious_ips": suspicious_ips,
            "suspicious_users": suspicious_users,
            "total_unique_ips": len(ip_counts),
            "total_unique_users": len(user_counts)
        }

    def detect_breaches(self, logs: list[dict]) -> list[dict]:
        breaches = []

        print("🔍 Starting breach detection analysis...")
        print("-" * 40)

        patterns = self.analyze_access_patterns(logs)

        for log_entry in logs:
            detected_issues = []

            if self.check_unauthorized_ip(log_entry):
                detected_issues.append("unauthorized_ip")

            if self.check_unauthorized_user(log_entry):
                detected_issues.append("unauthorized_user")

            if self.check_sensitive_file_access(log_entry):
                detected_issues.append("suspicious_object")

            if self.check_failed_authentication(log_entry):
                detected_issues.append("failed_auth")

            if (
                log_entry.get("source_ip") in patterns["suspicious_ips"]
                or log_entry.get("user") in patterns["suspicious_users"]
            ):
                detected_issues.append("unusual_activity")

            if detected_issues:
                breach = self.create_breach_record(log_entry, detected_issues, len(breaches) + 1)
                breaches.append(breach)

                print(f"🚨 Breach #{len(breaches)}: {breach['severity']} - {breach['description']}")
                print(f"   Source: {breach['source_ip']} | User: {breach['user']}")
                print(f"   Object: {breach['object_key']}")

        print(f"\n📈 Analysis Complete: {len(breaches)} breaches detected out of {len(logs)} log entries")
        return breaches

    def create_breach_record(self, log_entry: dict, issues: list[str], breach_number: int) -> dict:
        severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        severities = [self.breach_rules[issue]["severity"] for issue in issues]
        max_severity = max(severities, key=lambda severity: severity_order[severity])

        descriptions = [self.breach_rules[issue]["description"] for issue in issues]

        return {
            "breach_id": f"BREACH_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{breach_number:03d}",
            "timestamp": log_entry.get("timestamp"),
            "severity": max_severity,
            "description": "; ".join(descriptions),
            "source_ip": log_entry.get("source_ip"),
            "user": log_entry.get("user"),
            "bucket": log_entry.get("bucket"),
            "object_key": log_entry.get("object_key"),
            "action": log_entry.get("action"),
            "status_code": log_entry.get("status_code"),
            "detected_issues": issues,
            "impact_assessment": self.assess_impact(max_severity),
            "recommended_actions": self.get_recommended_actions(issues)
        }

    def assess_impact(self, severity: str) -> str:
        if severity == "HIGH":
            return "Critical: Immediate action required. Potential cloud data compromise."
        if severity == "MEDIUM":
            return "Moderate: Investigation needed. Possible security risk."
        return "Low: Monitor situation. Unusual but not immediately threatening."

    def get_recommended_actions(self, issues: list[str]) -> list[str]:
        actions = []

        if "unauthorized_ip" in issues:
            actions.extend(["Block suspicious IP address", "Review firewall or security group rules"])

        if "unauthorized_user" in issues:
            actions.extend(["Disable suspicious account", "Force credential rotation"])

        if "suspicious_object" in issues:
            actions.extend(["Audit object permissions", "Review data classification policy"])

        if "failed_auth" in issues:
            actions.extend(["Enable MFA", "Review failed login source"])

        if "unusual_activity" in issues:
            actions.extend(["Monitor access patterns", "Apply rate limiting"])

        return actions

    def save_breach_report(self, breaches: list[dict], filename: str):
        Path(filename).parent.mkdir(parents=True, exist_ok=True)

        report = {
            "report_timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "total_breaches": len(breaches),
            "severity_breakdown": self.get_severity_breakdown(breaches),
            "breaches": breaches
        }

        with open(filename, "w") as f:
            json.dump(report, f, indent=2)

        print(f"📋 Breach report saved to {filename}")

    def get_severity_breakdown(self, breaches: list[dict]) -> dict:
        breakdown = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for breach in breaches:
            breakdown[breach.get("severity", "LOW")] += 1

        return breakdown


def main():
    print("🔍 Starting Cloud Security Breach Detection")
    print("=" * 50)

    detector = SecurityBreachDetector("config/aws_config.json")

    log_files = glob.glob("logs/s3_access_logs_*.json")

    if not log_files:
        print("❌ No log files found. Please run the breach simulation first.")
        return

    latest_log = max(log_files, key=os.path.getctime)
    print(f"📁 Analyzing log file: {latest_log}")

    logs = detector.load_logs(latest_log)

    if not logs:
        return

    breaches = detector.detect_breaches(logs)

    report_filename = f"logs/breach_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    detector.save_breach_report(breaches, report_filename)

    print("\n" + "=" * 50)
    print("🎯 BREACH DETECTION SUMMARY")
    print("=" * 50)

    if breaches:
        severity_breakdown = detector.get_severity_breakdown(breaches)
        print(f"Total Breaches Detected: {len(breaches)}")
        print(f"High Severity: {severity_breakdown['HIGH']}")
        print(f"Medium Severity: {severity_breakdown['MEDIUM']}")
        print(f"Low Severity: {severity_breakdown['LOW']}")
        print(f"Report saved: {report_filename}")
    else:
        print("✅ No security breaches detected.")


if __name__ == "__main__":
    main()
