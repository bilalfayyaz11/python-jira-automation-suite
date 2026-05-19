import time
import json
import sys
import datetime
import logging
from pathlib import Path

import requests
from zapv2 import ZAPv2


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("threat_detection.log"),
        logging.StreamHandler(sys.stdout)
    ]
)


class AutomatedThreatDetection:
    def __init__(self, config):
        self.config = config
        self.zap = ZAPv2(
            proxies={
                "http": f"http://127.0.0.1:{config['zap_port']}",
                "https": f"http://127.0.0.1:{config['zap_port']}"
            }
        )

    def check_target_availability(self, target_url):
        try:
            response = requests.get(target_url, timeout=5)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def perform_security_scan(self, target_url):
        logging.info(f"Starting security scan on {target_url}")

        if not self.check_target_availability(target_url):
            logging.error(f"Target {target_url} is not accessible")
            return None

        spider_id = self.zap.spider.scan(target_url)

        while int(self.zap.spider.status(spider_id)) < 100:
            logging.info(f"Spider progress: {self.zap.spider.status(spider_id)}%")
            time.sleep(2)

        logging.info("Spider scan completed")

        ascan_id = self.zap.ascan.scan(target_url)

        while int(self.zap.ascan.status(ascan_id)) < 100:
            logging.info(f"Active scan progress: {self.zap.ascan.status(ascan_id)}%")
            time.sleep(5)

        logging.info("Active scan completed")

        alerts = self.zap.core.alerts()
        return self.generate_threat_report(alerts)

    def generate_threat_report(self, alerts):
        report = {
            "scan_timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "total_alerts": len(alerts),
            "summary": {
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 0,
                "informational": 0
            },
            "alerts": {
                "high_risk": [],
                "medium_risk": [],
                "low_risk": [],
                "informational": []
            }
        }

        for alert in alerts:
            risk = alert.get("risk", "Informational")

            alert_data = {
                "name": alert.get("alert", "Unknown"),
                "risk": risk,
                "description": alert.get("description", ""),
                "url": alert.get("url", ""),
                "param": alert.get("param", ""),
                "attack": alert.get("attack", ""),
                "evidence": alert.get("evidence", ""),
                "solution": alert.get("solution", ""),
                "reference": alert.get("reference", ""),
                "cwe_id": alert.get("cweid", ""),
                "wasc_id": alert.get("wascid", "")
            }

            if risk == "High":
                key = "high_risk"
            elif risk == "Medium":
                key = "medium_risk"
            elif risk == "Low":
                key = "low_risk"
            else:
                key = "informational"

            report["alerts"][key].append(alert_data)
            report["summary"][key] += 1

        return report

    def save_report(self, report, filename="threat_report.json"):
        with open(filename, "w") as f:
            json.dump(report, f, indent=2)

        logging.info(f"Report saved to {filename}")

    def create_demo_jira_issues(self, report, filename="automated_jira_issues.json"):
        issues = []
        project_key = "SEC"

        for risk_key, priority, risk_label in [
            ("high_risk", "Highest", "High"),
            ("medium_risk", "High", "Medium")
        ]:
            for alert in report["alerts"].get(risk_key, []):
                issue_key = f"{project_key}-{1001 + len(issues)}"

                issues.append({
                    "issue_key": issue_key,
                    "summary": f"[SECURITY] {alert['name']} - {risk_label} Risk",
                    "priority": priority,
                    "risk_level": risk_label,
                    "affected_url": alert.get("url", ""),
                    "parameter": alert.get("param", ""),
                    "solution": alert.get("solution", ""),
                    "labels": ["security", "automated", f"risk-{risk_label.lower()}"],
                    "created_at": datetime.datetime.now(datetime.UTC).isoformat()
                })

        with open(filename, "w") as f:
            json.dump(
                {
                    "total_issues_created": len(issues),
                    "issues": issues
                },
                f,
                indent=2
            )

        logging.info(f"Demo Jira issue report saved to {filename}")
        return issues

    def run_complete_scan(self, target_url):
        logging.info("Starting automated threat detection and reporting")

        report = self.perform_security_scan(target_url)

        if not report:
            logging.error("Security scan failed")
            return False

        self.save_report(report)

        logging.info("=== THREAT DETECTION SUMMARY ===")
        logging.info(f"Total alerts found: {report['total_alerts']}")
        logging.info(f"High risk: {report['summary']['high_risk']}")
        logging.info(f"Medium risk: {report['summary']['medium_risk']}")
        logging.info(f"Low risk: {report['summary']['low_risk']}")
        logging.info(f"Informational: {report['summary']['informational']}")

        issues = self.create_demo_jira_issues(report)
        logging.info(f"Created {len(issues)} Jira-style issues")

        return True


CONFIG = {
    "zap_port": 8080,
    "target_url": "http://localhost:5000"
}


if __name__ == "__main__":
    detector = AutomatedThreatDetection(CONFIG)
    success = detector.run_complete_scan(CONFIG["target_url"])

    if success:
        print("\n" + "=" * 60)
        print("AUTOMATED THREAT DETECTION COMPLETED SUCCESSFULLY")
        print("=" * 60)
        print("Check threat_report.json")
        print("Check threat_detection.log")
        print("Check automated_jira_issues.json")
    else:
        print("Threat detection failed. Check threat_detection.log")
