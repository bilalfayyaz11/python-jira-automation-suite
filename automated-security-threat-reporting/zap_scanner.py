from zapv2 import ZAPv2
import time
import json


class ZAPScanner:
    def __init__(self, zap_proxy="http://127.0.0.1:8080"):
        self.zap = ZAPv2(
            proxies={
                "http": zap_proxy,
                "https": zap_proxy
            }
        )

    def spider_target(self, target_url):
        print(f"Starting spider scan on {target_url}")
        scan_id = self.zap.spider.scan(target_url)

        while int(self.zap.spider.status(scan_id)) < 100:
            print(f"Spider progress: {self.zap.spider.status(scan_id)}%")
            time.sleep(2)

        print("Spider scan completed")
        return self.zap.spider.results(scan_id)

    def active_scan(self, target_url):
        print(f"Starting active scan on {target_url}")
        scan_id = self.zap.ascan.scan(target_url)

        while int(self.zap.ascan.status(scan_id)) < 100:
            print(f"Active scan progress: {self.zap.ascan.status(scan_id)}%")
            time.sleep(5)

        print("Active scan completed")
        return scan_id

    def get_alerts(self):
        return self.zap.core.alerts()

    def generate_report(self):
        alerts = self.get_alerts()

        report = {
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_alerts": len(alerts),
            "high_risk": [],
            "medium_risk": [],
            "low_risk": [],
            "informational": []
        }

        for alert in alerts:
            risk_level = alert.get("risk", "Informational")

            alert_data = {
                "name": alert.get("alert", "Unknown"),
                "risk": risk_level,
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

            if risk_level == "High":
                report["high_risk"].append(alert_data)
            elif risk_level == "Medium":
                report["medium_risk"].append(alert_data)
            elif risk_level == "Low":
                report["low_risk"].append(alert_data)
            else:
                report["informational"].append(alert_data)

        return report


if __name__ == "__main__":
    scanner = ZAPScanner()
    target = "http://localhost:5000"

    scanner.spider_target(target)
    scanner.active_scan(target)

    report = scanner.generate_report()

    with open("security_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"Scan completed. Found {report['total_alerts']} security issues.")
    print(f"High risk: {len(report['high_risk'])}")
    print(f"Medium risk: {len(report['medium_risk'])}")
    print(f"Low risk: {len(report['low_risk'])}")
    print(f"Informational: {len(report['informational'])}")
